"""Flask-powered web interface for the onboarding/offboarding toolkit."""
from __future__ import annotations

import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional
import unicodedata

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

from .ad_client import ADClient
from .config import (
    AppConfig,
    LDAPConfig,
    SyncConfig,
    StorageConfig,
    ensure_default_config,
    load_config,
    save_config,
)
from .models import Employee, JobRole, normalize_person_name
from .storage import load_job_roles
from .sync import run_sync_command


_TEMPLATE_FOLDER = Path(__file__).resolve().parent / "templates"
_DEFAULT_ATTRIBUTE_KEYS = ("title", "department", "company", "physicalDeliveryOfficeName", "employeeID")


def create_app(config_path: Optional[Path | str] = None) -> Flask:
    """Create and configure the Flask application."""

    resolved_config_path = Path(config_path) if config_path else None
    ensure_default_config(resolved_config_path)

    app = Flask(__name__, template_folder=str(_TEMPLATE_FOLDER))
    app.config["SECRET_KEY"] = os.environ.get("ONBOARD_WEB_SECRET", "onboard-offboard-secret")
    app.config["CONFIG_PATH"] = resolved_config_path
    app.config["JSON_SORT_KEYS"] = False

    register_routes(app)
    return app


def register_routes(app: Flask) -> None:
    """Attach all web routes to the provided Flask app."""

    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        config = _load_app_config(app)
        roles = _load_roles(config)
        return {
            "app_config": config,
            "job_roles": roles,
        }

    @app.route("/")
    def index() -> str:
        config = _load_app_config(app)
        return render_template("index.html", config=config)

    @app.route("/config", methods=["GET", "POST"])
    def edit_config() -> str:
        config = _load_app_config(app)

        if request.method == "POST":
            try:
                ldap = LDAPConfig(
                    server_uri=request.form.get("server_uri", "").strip(),
                    user_dn=request.form.get("user_dn", "").strip(),
                    password=request.form.get("password", ""),
                    base_dn=request.form.get("base_dn", "").strip(),
                    user_ou=request.form.get("user_ou", "").strip(),
                    use_ssl=request.form.get("use_ssl") == "on",
                    manager_search_filter=request.form.get("manager_search_filter", "(objectClass=user)").strip(),
                    manager_attributes=tuple(
                        filter(
                            None,
                            [attr.strip() for attr in request.form.get("manager_attributes", "").split(",") if attr.strip()],
                        )
                    )
                    or ("displayName", "mail", "title"),
                    mock_data_file=Path(request.form["mock_data_file"]).expanduser().resolve()
                    if request.form.get("mock_data_file")
                    else None,
                )
                sync = SyncConfig(
                    command=request.form.get("sync_command", "").strip(),
                    shell=request.form.get("sync_shell") == "on",
                    timeout=int(request.form.get("sync_timeout", config.sync.timeout or 120)),
                )
                storage = StorageConfig(
                    job_roles_file=Path(request.form.get("job_roles_file", config.storage.job_roles_file)).expanduser(),
                )
                updated = AppConfig(ldap=ldap, sync=sync, storage=storage)
                save_config(updated, app.config.get("CONFIG_PATH"))
                flash("Configuration updated successfully.", "success")
                return redirect(url_for("edit_config"))
            except Exception as exc:  # broad to surface validation errors to the UI
                flash(f"Unable to save configuration: {exc}", "error")

        return render_template("config.html", config=config)

    @app.route("/onboard", methods=["GET", "POST"])
    def onboard() -> str:
        config = _load_app_config(app)
        roles = _load_roles(config)
        managers, ous = _load_directory_context(config)
        companies, offices = _load_reference_values(config)
        email_domain = _email_domain_from_config(config)

        if request.method == "POST":
            try:
                raw_first_name = request.form.get("first_name", "")
                raw_last_name = request.form.get("last_name", "")
                first_name = normalize_person_name(raw_first_name)
                last_name = normalize_person_name(raw_last_name)
                username = request.form.get("username", "").strip()
                if not username:
                    username = _derive_username(first_name, last_name)
                email = _derive_email(username, email_domain) or request.form.get("email", "").strip()
                role_name = request.form.get("job_role", "")
                password = request.form.get("password", "") or None
                manager_search = request.form.get("manager_search", "").strip()
                manager_dn = request.form.get("manager_dn") or None
                chosen_ou = request.form.get("user_ou") or None
                telephone_number = request.form.get("telephone_number", "").strip()
                mobile_number = request.form.get("mobile_number", "").strip()
                company_name = request.form.get("company", "").strip()
                office_name = request.form.get("office", "").strip()
                attributes = _parse_attributes(request.form.get("attributes", ""))

                if not all([first_name, last_name, username, email, role_name]):
                    raise ValueError("All fields except password and attributes are required.")

                role = roles.get(role_name)
                if not role:
                    role = JobRole(
                        name=role_name,
                        user_ou=config.ldap.user_ou,
                        default_manager_dn=None,
                        attributes={"title": role_name} if role_name else {},
                    )
                if not manager_dn and manager_search:
                    manager_dn = _resolve_manager_dn(manager_search, config, limit=3)
                effective_manager = manager_dn or role.default_manager_dn
                if not effective_manager:
                    raise ValueError("A manager must be selected or defined in the job role.")

                if telephone_number:
                    attributes["telephoneNumber"] = telephone_number
                else:
                    attributes.pop("telephoneNumber", None)
                if mobile_number:
                    attributes["mobile"] = mobile_number
                else:
                    attributes.pop("mobile", None)
                if company_name:
                    attributes["company"] = company_name
                else:
                    attributes.pop("company", None)
                if office_name:
                    attributes["physicalDeliveryOfficeName"] = office_name
                else:
                    attributes.pop("physicalDeliveryOfficeName", None)

                job_role = replace(role, user_ou=chosen_ou or role.user_ou)
                employee = Employee(
                    first_name=first_name,
                    last_name=last_name,
                    username=username,
                    email=email,
                    job_role=role_name,
                    manager_dn=effective_manager,
                    attributes=attributes,
                )

                with ADClient(config.ldap) as client:
                    result = client.create_user(employee, job_role, password=password)

                _trigger_sync(config)
                flash(
                    f"Provisioned {result.get('sAMAccountName')} in {result.get('distinguished_name')}.",
                    "success",
                )
                return redirect(url_for("index"))
            except Exception as exc:
                flash(f"Unable to onboard user: {exc}", "error")

        generated_username = _derive_username(
            normalize_person_name(request.form.get("first_name", "")),
            normalize_person_name(request.form.get("last_name", "")),
        )
        generated_email = _derive_email(
            request.form.get("username", "").strip() or generated_username,
            email_domain,
        )
        return render_template(
            "onboard.html",
            managers=managers,
            ous=ous,
            email_domain=email_domain,
            generated_email=generated_email,
            generated_username=generated_username,
            companies=companies,
            offices=offices,
        )

    @app.get("/api/job-titles")
    def api_job_titles() -> Any:
        config = _load_app_config(app)
        roles = _load_roles(config)
        query = request.args.get("q", "").strip()
        limit = _parse_api_limit(request.args.get("limit"))

        titles: List[str] = []
        seen: set[str] = set()
        lowered_query = query.lower() if query else None

        def _add_title(candidate: Optional[str]) -> None:
            if not candidate:
                return
            title = candidate.strip()
            if not title:
                return
            if lowered_query and lowered_query not in title.lower():
                return
            if title not in seen:
                seen.add(title)
                titles.append(title)

        for name in roles:
            _add_title(name)

        ad_error: Optional[str] = None
        try:
            with ADClient(config.ldap) as client:
                for title in client.list_job_titles(query or None, limit):
                    _add_title(title)
        except Exception as exc:  # pragma: no cover - graceful degradation for API errors
            ad_error = str(exc)

        titles.sort(key=str.casefold)
        items = titles[:limit]
        payload: Dict[str, Any] = {"items": items}
        if ad_error:
            payload["error"] = ad_error
        return jsonify(payload)

    @app.get("/api/companies")
    def api_companies() -> Any:
        config = _load_app_config(app)
        roles = _load_roles(config)
        query = request.args.get("q", "").strip()
        limit = _parse_api_limit(request.args.get("limit"))

        companies: List[str] = []
        seen: set[str] = set()
        lowered_query = query.lower() if query else None

        def _add_company(value: Optional[str]) -> None:
            if not value:
                return
            company = value.strip()
            if not company:
                return
            if lowered_query and lowered_query not in company.lower():
                return
            if company not in seen:
                seen.add(company)
                companies.append(company)

        for role in roles.values():
            _add_company(role.attributes.get("company"))

        ad_error: Optional[str] = None
        try:
            with ADClient(config.ldap) as client:
                for company in client.list_companies(query or None, limit):
                    _add_company(company)
        except Exception as exc:  # pragma: no cover
            ad_error = str(exc)

        companies.sort(key=str.casefold)
        items = companies[:limit]
        payload: Dict[str, Any] = {"items": items}
        if ad_error:
            payload["error"] = ad_error
        return jsonify(payload)

    @app.get("/api/offices")
    def api_offices() -> Any:
        config = _load_app_config(app)
        query = request.args.get("q", "").strip()
        limit = _parse_api_limit(request.args.get("limit"))

        offices: List[str] = []
        ad_error: Optional[str] = None
        try:
            with ADClient(config.ldap) as client:
                offices = client.list_offices(query or None, limit)
        except Exception as exc:  # pragma: no cover
            ad_error = str(exc)

        if not offices:
            roles = _load_roles(config)
            lowered = query.lower() if query else None
            for role in roles.values():
                candidate = role.attributes.get("physicalDeliveryOfficeName")
                if not candidate:
                    continue
                candidate = candidate.strip()
                if not candidate:
                    continue
                if lowered and lowered not in candidate.lower():
                    continue
                offices.append(candidate)

        offices = sorted(dict.fromkeys(offices), key=str.casefold)
        payload: Dict[str, Any] = {"items": offices[:limit]}
        if ad_error:
            payload["error"] = ad_error
        return jsonify(payload)

    @app.get("/api/managers")
    def api_managers() -> Any:
        config = _load_app_config(app)
        query = request.args.get("q", "").strip()
        limit = _parse_api_limit(request.args.get("limit"))
        if not query:
            return jsonify({"items": []})

        ad_error: Optional[str] = None
        results: List[Dict[str, Any]] = []
        try:
            with ADClient(config.ldap) as client:
                results = client.search_managers(query, limit)
                if not results:
                    user_results = client.search_users(
                        query,
                        attributes=[
                            "distinguishedName",
                            "displayName",
                            "mail",
                            "title",
                            "sAMAccountName",
                            "userPrincipalName",
                        ],
                    )
                    for entry in user_results:
                        dn = entry.get("distinguishedName")
                        if not dn:
                            continue
                        results.append(
                            {
                                "distinguishedName": dn,
                                "displayName": entry.get("displayName"),
                                "mail": entry.get("mail"),
                                "title": entry.get("title"),
                                "sAMAccountName": entry.get("sAMAccountName"),
                                "userPrincipalName": entry.get("userPrincipalName"),
                            }
                        )
                        if len(results) >= limit:
                            break
        except Exception as exc:  # pragma: no cover - graceful degradation
            ad_error = str(exc)

        if not results:
            managers, _ = _load_directory_context(config)
            lowered = query.lower()
            for manager in managers:
                haystack = " ".join(
                    str(manager.get(key, ""))
                    for key in ("displayName", "distinguishedName", "mail", "title")
                ).lower()
                if lowered in haystack:
                    results.append(
                        {
                            "distinguishedName": manager.get("distinguishedName"),
                            "displayName": manager.get("displayName"),
                            "mail": manager.get("mail"),
                            "sAMAccountName": manager.get("sAMAccountName"),
                            "title": manager.get("title"),
                        }
                    )
                if len(results) >= limit:
                    break

        payload: Dict[str, Any] = {"items": results[:limit]}
        if ad_error:
            payload["error"] = ad_error
        return jsonify(payload)

    @app.get("/api/ous")
    def api_organizational_units() -> Any:
        config = _load_app_config(app)
        query = request.args.get("q", "").strip()
        limit = _parse_api_limit(request.args.get("limit"))

        ous: List[str] = []
        ad_error: Optional[str] = None
        try:
            with ADClient(config.ldap) as client:
                ous = client.search_organizational_units(query or None, limit)
        except Exception as exc:  # pragma: no cover - graceful degradation
            ad_error = str(exc)

        if not ous:
            _, cached_ous = _load_directory_context(config)
            lowered = query.lower() if query else None
            for entry in cached_ous:
                if lowered and lowered not in entry.lower():
                    continue
                ous.append(entry)
                if len(ous) >= limit:
                    break

        payload: Dict[str, Any] = {"items": ous[:limit]}
        if ad_error:
            payload["error"] = ad_error
        return jsonify(payload)

    @app.route("/clone", methods=["GET", "POST"])
    def clone_user() -> str:
        config = _load_app_config(app)
        roles = _load_roles(config)
        managers, ous = _load_directory_context(config)
        companies, offices = _load_reference_values(config)

        query = request.args.get("query", "").strip()
        user_dn = request.args.get("user_dn")
        search_results: List[Dict[str, Any]] = []
        selected_user: Optional[Dict[str, Any]] = None

        if query:
            try:
                with ADClient(config.ldap) as client:
                    search_results = client.search_users(query)
            except Exception as exc:
                flash(f"Unable to search for users: {exc}", "error")

        if user_dn:
            try:
                with ADClient(config.ldap) as client:
                    selected_user = client.get_user(
                        user_dn,
                        attributes=[
                            "manager",
                            "title",
                            "department",
                            "company",
                            "mail",
                            "telephoneNumber",
                            "mobile",
                            "displayName",
                            "sAMAccountName",
                            "userPrincipalName",
                            "physicalDeliveryOfficeName",
                        ],
                    )
            except Exception as exc:
                flash(f"Unable to load selected user: {exc}", "error")

        template_manager_dn: Optional[str] = None
        template_manager_display: Optional[str] = None
        if selected_user:
            template_manager_dn = selected_user.get("manager")
            if template_manager_dn:
                template_manager_display = template_manager_dn
                try:
                    with ADClient(config.ldap) as client:
                        manager_info = client.get_user(
                            template_manager_dn,
                            attributes=[
                                "displayName",
                                "mail",
                                "sAMAccountName",
                                "userPrincipalName",
                                "title",
                            ],
                        )
                    if manager_info:
                        pieces = [
                            manager_info.get("displayName"),
                            manager_info.get("title"),
                            manager_info.get("mail"),
                            manager_info.get("sAMAccountName"),
                        ]
                        template_manager_display = " ".join(
                            part for part in pieces if part
                        ).strip() or template_manager_dn
                except Exception:
                    template_manager_display = template_manager_dn

        email_domain = _email_domain_from_config(config)

        if request.method == "POST":
            try:
                raw_first_name = request.form.get("first_name", "")
                raw_last_name = request.form.get("last_name", "")
                first_name = normalize_person_name(raw_first_name)
                last_name = normalize_person_name(raw_last_name)
                username = request.form.get("username", "").strip()
                if not username:
                    username = _derive_username(first_name, last_name)
                role_name = request.form.get("job_role", "").strip()
                email = _derive_email(username, email_domain) or request.form.get("email", "").strip()
                password = request.form.get("password", "") or None
                manager_search = request.form.get("manager_search", "").strip()
                explicit_manager_dn = request.form.get("manager_dn") or None
                chosen_ou = request.form.get("user_ou") or None
                telephone_number = request.form.get("telephone_number", "").strip()
                mobile_number = request.form.get("mobile_number", "").strip()
                company_name = request.form.get("company", "").strip()
                office_name = request.form.get("office", "").strip()
                attributes = _parse_attributes(request.form.get("attributes", ""))

                if not all([first_name, last_name, username, email, role_name]):
                    raise ValueError("All fields except password and attributes are required.")

                role = roles.get(role_name)
                if not role:
                    role = JobRole(
                        name=role_name,
                        user_ou=config.ldap.user_ou,
                        default_manager_dn=None,
                        attributes={"title": role_name} if role_name else {},
                    )

                manager_dn = explicit_manager_dn
                if not manager_dn and manager_search:
                    manager_dn = _resolve_manager_dn(manager_search, config, limit=5)
                if not manager_dn:
                    manager_dn = role.default_manager_dn or template_manager_dn

                if not manager_dn:
                    raise ValueError("A manager must be selected or defined in the job role.")

                if telephone_number:
                    attributes["telephoneNumber"] = telephone_number
                else:
                    attributes.pop("telephoneNumber", None)
                if mobile_number:
                    attributes["mobile"] = mobile_number
                else:
                    attributes.pop("mobile", None)
                if company_name:
                    attributes["company"] = company_name
                else:
                    attributes.pop("company", None)
                if office_name:
                    attributes["physicalDeliveryOfficeName"] = office_name
                else:
                    attributes.pop("physicalDeliveryOfficeName", None)

                employee = Employee(
                    first_name=first_name,
                    last_name=last_name,
                    username=username,
                    email=email,
                    job_role=role_name,
                    manager_dn=manager_dn,
                    attributes=attributes,
                )

                chosen_ou = chosen_ou or role.user_ou
                job_role = replace(role, user_ou=chosen_ou or role.user_ou)

                with ADClient(config.ldap) as client:
                    result = client.create_user(employee, job_role, password=password)

                _trigger_sync(config)
                flash(
                    f"Cloned user into account {result.get('sAMAccountName')}.",
                    "success",
                )
                return redirect(url_for("index"))
            except Exception as exc:
                flash(f"Unable to clone user: {exc}", "error")

        attribute_defaults = _format_attributes(selected_user)
        default_manager = template_manager_dn
        default_manager_label = template_manager_display
        default_ou = _ou_from_dn(selected_user.get("distinguishedName")) if selected_user else None
        generated_username = _derive_username(
            normalize_person_name(request.form.get("first_name", "")),
            normalize_person_name(request.form.get("last_name", "")),
        )
        generated_email = _derive_email(
            request.form.get("username", "").strip() or generated_username,
            email_domain,
        )

        return render_template(
            "clone.html",
            query=query,
            search_results=search_results,
            selected_user=selected_user,
            default_attributes=attribute_defaults,
            default_manager=default_manager,
            default_manager_label=default_manager_label,
            default_ou=default_ou,
            managers=managers,
            ous=ous,
            companies=companies,
            offices=offices,
            email_domain=email_domain,
            generated_email=generated_email,
            generated_username=generated_username,
        )

    @app.route("/delete", methods=["GET", "POST"])
    def delete_user() -> str:
        config = _load_app_config(app)
        query = request.args.get("query", "").strip()
        search_results: List[Dict[str, Any]] = []

        if query:
            try:
                with ADClient(config.ldap) as client:
                    search_results = client.search_users(query)
            except Exception as exc:
                flash(f"Unable to search for users: {exc}", "error")

        if request.method == "POST":
            user_dn = request.form.get("user_dn")
            if not user_dn:
                flash("Select a user to delete.", "error")
            else:
                try:
                    with ADClient(config.ldap) as client:
                        deleted = client.delete_user(user_dn)
                    if not deleted:
                        raise RuntimeError("User was not deleted.")
                    _trigger_sync(config)
                    flash(f"Removed {user_dn} and triggered sync.", "success")
                    return redirect(url_for("delete_user"))
                except Exception as exc:
                    flash(f"Unable to delete user: {exc}", "error")

        return render_template(
            "delete.html",
            query=query,
            search_results=search_results,
        )


def _load_app_config(app: Flask) -> AppConfig:
    return load_config(app.config.get("CONFIG_PATH"))


def _load_roles(config: AppConfig) -> Dict[str, JobRole]:
    return load_job_roles(config.storage.job_roles_file)


def _load_directory_context(config: AppConfig) -> tuple[List[Dict[str, Any]], List[str]]:
    managers: List[Dict[str, Any]] = []
    ous: List[str] = []

    try:
        with ADClient(config.ldap) as client:
            managers = client.list_potential_managers()
            tree = client.fetch_directory_tree(depth=4)
            ous = _flatten_ous(tree)
    except Exception as exc:
        flash_message = f"Unable to load managers/OUs from the directory: {exc}"
        flash(flash_message, "error")

    return managers, ous


def _load_reference_values(config: AppConfig) -> tuple[List[str], List[str]]:
    companies: List[str] = []
    offices: List[str] = []

    try:
        with ADClient(config.ldap) as client:
            companies = client.list_companies(limit=200)
            offices = client.list_offices(limit=200)
    except Exception as exc:
        flash(f"Unable to load company/office options: {exc}", "error")

    return companies, offices


def _flatten_ous(tree: Dict[str, Any]) -> List[str]:
    entries: List[str] = []

    def _walk(node: Dict[str, Any]) -> None:
        name = node.get("name")
        if name and name.upper().startswith("OU="):
            entries.append(name)
        for child in node.get("children", []):
            _walk(child)

    _walk(tree)
    return entries


def _parse_attributes(raw: str) -> Dict[str, Any]:
    attributes: Dict[str, Any] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise ValueError("Attributes must be provided as key=value pairs, one per line.")
        key, value = stripped.split("=", 1)
        attributes[key.strip()] = value.strip()
    return attributes


def _format_attributes(user: Optional[Dict[str, Any]]) -> str:
    if not user:
        return ""

    attributes: Dict[str, Any] = {}
    for key in _DEFAULT_ATTRIBUTE_KEYS:
        value = user.get(key)
        if value:
            attributes[key] = value

    return "\n".join(f"{key}={value}" for key, value in attributes.items())


def _ou_from_dn(distinguished_name: Optional[str]) -> Optional[str]:
    if not distinguished_name or "," not in distinguished_name:
        return None
    return distinguished_name.split(",", 1)[1]


def _parse_api_limit(raw: Optional[str], default: int = 25, maximum: int = 100) -> int:
    try:
        value = int(raw) if raw is not None else default
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, maximum))


def _resolve_manager_dn(query: str, config: AppConfig, limit: int = 5) -> Optional[str]:
    """Resolve a free-form manager input to a distinguished name."""

    cleaned = query.strip()
    if not cleaned:
        return None

    try:
        with ADClient(config.ldap) as client:
            # Try to resolve by direct DN first.
            if cleaned.upper().startswith("CN="):
                return cleaned

            results = client.search_managers(cleaned, limit=limit)
            if not results:
                results = client.search_users(
                    cleaned,
                    attributes=[
                        "distinguishedName",
                        "displayName",
                        "mail",
                        "title",
                        "sAMAccountName",
                        "userPrincipalName",
                    ],
                )
    except Exception as exc:
        raise ValueError(f"Unable to search for manager: {exc}") from exc

    matches: List[Dict[str, Any]] = []
    for entry in results:
        dn = entry.get("distinguishedName")
        if not dn:
            continue
        matches.append(
            {
                "distinguishedName": dn,
                "displayName": entry.get("displayName"),
                "mail": entry.get("mail"),
                "title": entry.get("title"),
                "sAMAccountName": entry.get("sAMAccountName"),
                "userPrincipalName": entry.get("userPrincipalName"),
            }
        )
    if not matches:
        raise ValueError(f"No manager found matching '{cleaned}'.")

    normalized = cleaned.lower()
    exact_matches = []
    for entry in matches:
        fields = [
            entry.get("displayName", ""),
            entry.get("mail", ""),
            entry.get("sAMAccountName", ""),
            entry.get("userPrincipalName", ""),
        ]
        if any(str(field).lower() == normalized for field in fields if field):
            exact_matches.append(entry)

    if len(exact_matches) == 1:
        return exact_matches[0]["distinguishedName"]

    if len(matches) == 1:
        return matches[0]["distinguishedName"]

    if exact_matches:
        # Multiple exact matches, still ambiguous.
        raise ValueError(
            f"Multiple managers match '{cleaned}'. "
            "Refine your search and select an entry from the suggestions."
        )

    if len(matches) > 1:
        raise ValueError(
            f"Multiple managers match '{cleaned}'. "
            "Refine your search and select an entry from the suggestions."
        )
    return matches[0]["distinguishedName"]


def _email_domain_from_config(config: AppConfig) -> Optional[str]:
    base_dn = config.ldap.base_dn
    if not base_dn:
        return None
    parts = []
    for segment in base_dn.split(","):
        segment = segment.strip()
        if segment.upper().startswith("DC="):
            parts.append(segment.split("=", 1)[1])
    return ".".join(parts) if parts else None


def _derive_email(username: str, domain: Optional[str]) -> Optional[str]:
    if not username or not domain:
        return None
    return f"{username}@{domain}"


def _slugify_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]", "", ascii_value.lower())


def _derive_username(first_name: str, last_name: str) -> str:
    parts = [
        _slugify_name(first_name),
        _slugify_name(last_name),
    ]
    filtered = [part for part in parts if part]
    if not filtered:
        return ""
    if len(filtered) == 1:
        return filtered[0]
    return ".".join(filtered)


def _trigger_sync(config: AppConfig) -> None:
    try:
        run_sync_command(config.sync)
    except RuntimeError as exc:
        flash(f"Directory sync reported a problem: {exc}", "error")


def main() -> None:
    """Run the development server."""

    app = create_app()
    app.run(
        host=os.environ.get("ONBOARD_WEB_HOST", "0.0.0.0"),
        port=int(os.environ.get("ONBOARD_WEB_PORT", "5000")),
        debug=os.environ.get("ONBOARD_WEB_DEBUG") == "1",
    )


if __name__ == "__main__":
    main()
