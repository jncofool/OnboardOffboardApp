"""Flask-powered web interface for the onboarding/offboarding toolkit."""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import threading
import time
import unicodedata
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

import msal
import requests
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask import has_request_context

from .ad_client import ADClient
from .config import (
    AppConfig,
    AuthConfig,
    LDAPConfig,
    M365Config,
    SyncConfig,
    StorageConfig,
    ensure_default_config,
    load_config,
    save_config,
)
from .models import Employee, JobRole, LicenseSelection, normalize_person_name
from .storage import load_job_roles, save_job_roles
from .sync import run_sync_command
from .m365_client import (
    CatalogSnapshot,
    M365Client,
    M365ClientError,
    M365ConfigurationError,
)
from .license_jobs import LicenseJob, LicenseJobStore


_TEMPLATE_FOLDER = Path(__file__).resolve().parent / "templates"
_DEFAULT_ATTRIBUTE_KEYS = ("title", "department", "company", "physicalDeliveryOfficeName", "employeeID")
_LICENSE_WORKER_INTERVAL = 30
_LICENSE_INITIAL_DELAY_SECONDS = 90
_LICENSE_RETRY_SCHEDULE = (30, 30, 60, 120, 300)
_AUTH_EXEMPT_ENDPOINTS = {"login", "logout", "auth_callback", "static"}
_DEFAULT_AUTH_SCOPES = ("https://graph.microsoft.com/User.Read",)
_RESERVED_AUTH_SCOPES = {"openid", "profile", "offline_access"}


def _parse_license_selections(raw_values: Iterable[str]) -> List[LicenseSelection]:
    selections: List[LicenseSelection] = []
    for raw in raw_values or []:
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except Exception:
            continue
        try:
            selection = LicenseSelection.from_dict(payload).normalized()
        except Exception:
            continue
        if selection.sku_id:
            selections.append(selection)
    return selections


def _merge_license_selections(selections: Iterable[LicenseSelection]) -> List[LicenseSelection]:
    merged: Dict[str, LicenseSelection] = {}
    for selection in selections or []:
        if not selection or not selection.sku_id:
            continue
        normalized = selection.normalized()
        existing = merged.get(normalized.sku_id)
        if existing:
            combined = set(existing.disabled_plans)
            combined.update(normalized.disabled_plans)
            merged[normalized.sku_id] = LicenseSelection(
                sku_id=normalized.sku_id,
                disabled_plans=sorted(combined),
            )
        else:
            merged[normalized.sku_id] = normalized
    return list(merged.values())


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

    _ensure_license_worker(app)

    @app.before_request
    def _enforce_authentication() -> Optional[Any]:
        config = _load_app_config(app)
        current_user = session.get("user")
        g.current_user = current_user
        if not config.auth.enabled:
            return None

        endpoint = request.endpoint or ""
        if endpoint.startswith("static") or endpoint in _AUTH_EXEMPT_ENDPOINTS:
            return None

        if current_user:
            return None

        session["post_login_redirect"] = request.url
        return redirect(url_for("login"))

    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        config = _load_app_config(app)
        roles = _load_roles(config)
        return {
            "app_config": config,
            "job_roles": roles,
            "current_user": session.get("user"),
        }

    @app.route("/login")
    def login() -> Any:
        config = _load_app_config(app)
        if not config.auth.enabled:
            flash("Authentication is not enabled.", "error")
            return redirect(url_for("index"))
        if not config.auth.has_credentials:
            flash("Authentication is enabled but not fully configured.", "error")
            return redirect(url_for("index"))

        state = secrets.token_urlsafe(32)
        session["auth_state"] = state
        next_url = request.args.get("next") or session.get("post_login_redirect") or url_for("index")
        session["post_login_redirect"] = next_url

        client = _build_msal_client(config.auth)
        redirect_uri = _auth_redirect_uri(config.auth)
        requested_scopes = list(config.auth.scopes or _DEFAULT_AUTH_SCOPES)
        scopes = [scope for scope in requested_scopes if scope.lower() not in _RESERVED_AUTH_SCOPES]
        if not scopes:
            scopes = list(_DEFAULT_AUTH_SCOPES)
        auth_url = client.get_authorization_request_url(
            scopes=scopes,
            state=state,
            redirect_uri=redirect_uri,
            prompt="select_account",
        )
        return redirect(auth_url)

    @app.route("/logout")
    def logout() -> Any:
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("index"))

    @app.route("/auth/callback")
    def auth_callback() -> Any:
        config = _load_app_config(app)
        if not config.auth.enabled:
            flash("Authentication is not enabled.", "error")
            return redirect(url_for("index"))

        expected_state = session.get("auth_state")
        if not expected_state or expected_state != request.args.get("state"):
            flash("Authentication response could not be validated. Please try again.", "error")
            return redirect(url_for("login"))
        session.pop("auth_state", None)

        if "error" in request.args:
            flash(request.args.get("error_description") or "Sign-in was cancelled.", "error")
            return redirect(url_for("login"))

        code = request.args.get("code")
        if not code:
            flash("Missing authorization code.", "error")
            return redirect(url_for("login"))

        client = _build_msal_client(config.auth)
        redirect_uri = _auth_redirect_uri(config.auth)
        token_scopes = list(config.auth.scopes or _DEFAULT_AUTH_SCOPES)
        app.logger.info(
            "Auth callback: exchanging authorization code for scopes=%s redirect_uri=%s state=%s",
            token_scopes,
            redirect_uri,
            expected_state,
        )
        token_result = client.acquire_token_by_authorization_code(
            code,
            scopes=token_scopes,
            redirect_uri=redirect_uri,
        )
        if "access_token" not in token_result:
            message = token_result.get("error_description") or "Unable to complete sign-in."
            app.logger.error(
                "Auth callback: token acquisition failed (error=%s, error_description=%s, correlation_id=%s)",
                token_result.get("error"),
                token_result.get("error_description"),
                token_result.get("correlation_id"),
            )
            flash(message, "error")
            return redirect(url_for("login"))

        claims = token_result.get("id_token_claims") or {}
        subject = claims.get("preferred_username") or claims.get("oid") or "unknown"
        allowed_groups = set(config.auth.allowed_groups or [])
        app.logger.info(
            "Auth callback: allowed group ids=%s",
            sorted(allowed_groups) if allowed_groups else [],
        )
        user_groups = _extract_user_groups(claims, token_result, app.logger)
        app.logger.info(
            "Auth callback: user=%s oid=%s resolved_groups=%s",
            subject,
            claims.get("oid"),
            sorted(user_groups),
        )
        if allowed_groups and user_groups.isdisjoint(allowed_groups):
            app.logger.warning(
                "Auth callback: denying user=%s oid=%s (required groups=%s, resolved_groups=%s)",
                subject,
                claims.get("oid"),
                sorted(allowed_groups),
                sorted(user_groups),
            )
            flash("You do not have access to this application.", "error")
            return redirect(url_for("login"))

        session["user"] = {
            "name": claims.get("name") or claims.get("preferred_username") or "Signed-in user",
            "upn": claims.get("preferred_username") or claims.get("email"),
            "oid": claims.get("oid"),
            "groups": list(user_groups),
        }
        destination = session.pop("post_login_redirect", url_for("index"))
        flash("Signed in successfully.", "success")
        return redirect(destination)

    @app.route("/")
    def index() -> str:
        config = _load_app_config(app)
        return render_template("index.html", config=config)

    @app.route("/config", methods=["GET", "POST"])
    def edit_config() -> str:
        config = _load_app_config(app)
        roles = _load_roles(config)

        if request.method == "POST":
            try:
                password_input = request.form.get("password", "")
                ldap_password = password_input if password_input else config.ldap.password
                
                ldap = LDAPConfig(
                    server_uri=request.form.get("server_uri", "").strip(),
                    user_dn=request.form.get("user_dn", "").strip(),
                    password=ldap_password,
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
                    group_search_base=request.form.get("group_search_base", "").strip() or None,
                )
                sync = SyncConfig(
                    command=request.form.get("sync_command", "").strip(),
                    shell=request.form.get("sync_shell") == "on",
                    timeout=int(request.form.get("sync_timeout", config.sync.timeout or 120)),
                )
                storage = StorageConfig(
                    job_roles_file=Path(
                        request.form.get("job_roles_file", config.storage.job_roles_file)
                    ).expanduser(),
                    license_jobs_file=Path(
                        request.form.get("license_jobs_file", config.storage.license_jobs_file)
                    ).expanduser(),
                )

                current_m365 = getattr(config, "m365", M365Config())
                current_auth = getattr(config, "auth", AuthConfig())
                tenant_id = request.form.get("m365_tenant_id", "").strip() or None
                client_id = request.form.get("m365_client_id", "").strip() or None
                secret_input = request.form.get("m365_client_secret", "")
                client_secret = secret_input.strip() or current_m365.client_secret

                cache_path_raw = request.form.get("m365_sku_cache_file", "").strip()
                cache_path = (
                    Path(cache_path_raw).expanduser()
                    if cache_path_raw
                    else current_m365.sku_cache_file
                )
                cache_ttl_raw = request.form.get("m365_cache_ttl_minutes", "").strip()
                try:
                    cache_ttl = (
                        int(cache_ttl_raw)
                        if cache_ttl_raw
                        else current_m365.cache_ttl_minutes
                    )
                except ValueError as exc:
                    raise ValueError("Cache TTL must be a whole number of minutes.") from exc
                default_usage_location_input = (
                    request.form.get("m365_default_usage_location", "").strip().upper()
                )
                if default_usage_location_input:
                    default_usage_location = default_usage_location_input
                else:
                    default_usage_location = current_m365.default_usage_location

                cert_thumbprint_input = request.form.get("m365_cert_thumbprint", "").strip()
                cert_thumbprint = cert_thumbprint_input or current_m365.cert_thumbprint
                exo_org_input = request.form.get("m365_exo_organization", "").strip()
                exo_organization = exo_org_input or current_m365.exo_organization

                m365 = M365Config(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    sku_cache_file=cache_path,
                    cache_ttl_minutes=max(1, cache_ttl),
                    default_usage_location=default_usage_location,
                    cert_thumbprint=cert_thumbprint,
                    exo_organization=exo_organization,
                )

                auth_enabled = request.form.get("auth_enabled") == "on"
                auth_secret_input = request.form.get("auth_client_secret", "")
                auth_client_secret = auth_secret_input.strip() or current_auth.client_secret
                allowed_groups_raw = request.form.get("auth_allowed_groups", "")
                allowed_groups = tuple(
                    filter(
                        None,
                        [
                            line.strip()
                            for line in allowed_groups_raw.splitlines()
                        ],
                    )
                )
                auth = AuthConfig(
                    enabled=auth_enabled,
                    tenant_id=request.form.get("auth_tenant_id", "").strip() or None,
                    client_id=request.form.get("auth_client_id", "").strip() or None,
                    client_secret=auth_client_secret,
                    redirect_uri=request.form.get("auth_redirect_uri", "").strip() or None,
                    allowed_groups=allowed_groups,
                    scopes=current_auth.scopes,
                )

                updated = AppConfig(ldap=ldap, sync=sync, storage=storage, m365=m365, auth=auth)
                save_config(updated, app.config.get("CONFIG_PATH"))
                flash("Configuration updated successfully.", "success")
                return redirect(url_for("edit_config"))
            except Exception as exc:  # broad to surface validation errors to the UI
                flash(f"Unable to save configuration: {exc}", "error")

        roles_json = [_serialize_role(role) for role in roles.values()]
        m365_status = _build_m365_status(app, config)
        job_titles = _preload_job_titles(config, roles)
        return render_template(
            "config.html",
            config=config,
            roles_json=roles_json,
            m365_status=m365_status,
            job_titles=job_titles,
        )

    @app.route("/onboard", methods=["GET", "POST"])
    def onboard() -> str:
        config = _load_app_config(app)
        roles = _load_roles(config)
        managers, ous = _load_directory_context(config)
        companies, offices = _load_reference_values(config)
        email_domain = _email_domain_from_config(config)
        role_groups = {name: list(role.groups) for name, role in roles.items()}
        role_license_defaults = {
            name: {
                "licenses": [selection.to_dict() for selection in role.licenses],
                "license_sku_id": role.license_sku_id,
                "disabled_service_plans": role.disabled_service_plans,
            }
            for name, role in roles.items()
        }
        selected_groups = _dedupe_preserve(request.form.getlist("groups"))
        legacy_license_sku = (request.form.get("license_sku") or "").strip()
        legacy_disabled_plans = _dedupe_preserve(request.form.getlist("license_disabled_plan"))
        legacy_selection = (
            LicenseSelection(sku_id=legacy_license_sku, disabled_plans=legacy_disabled_plans).normalized()
            if legacy_license_sku
            else None
        )
        parsed_selections = _parse_license_selections(request.form.getlist("license_selection"))
        if legacy_selection:
            parsed_selections.append(legacy_selection)
        selected_license_selections = _merge_license_selections(parsed_selections)
        m365_status = _build_m365_status(app, config)

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
                role_name = request.form.get("job_role", "").strip()
                password = request.form.get("password", "").strip()
                manager_search = request.form.get("manager_search", "").strip()
                manager_dn = request.form.get("manager_dn") or None
                chosen_ou = request.form.get("user_ou") or None
                telephone_number = request.form.get("telephone_number", "").strip()
                mobile_number = request.form.get("mobile_number", "").strip()
                company_name = request.form.get("company", "").strip()
                office_name = request.form.get("office", "").strip()
                attributes = _parse_attributes(request.form.get("attributes", ""))
                selected_groups = _dedupe_preserve(request.form.getlist("groups"))
                assignable_groups, skipped_groups = _filter_assignable_groups(selected_groups, config)
                if skipped_groups:
                    flash(
                        "Skipped groups outside the managed scope: "
                        + ", ".join(skipped_groups),
                        "warning",
                    )
                selected_groups = assignable_groups
                assignable_groups, skipped_groups = _filter_assignable_groups(selected_groups, config)
                if skipped_groups:
                    flash(
                        "Skipped groups outside the managed scope: "
                        + ", ".join(skipped_groups),
                        "warning",
                    )
                selected_groups = assignable_groups

                if not all([first_name, last_name, username, email, role_name]):
                    raise ValueError("All fields except attributes are required.")
                if not password:
                    raise ValueError("A temporary password is required.")

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

                parsed_form_selections = _parse_license_selections(request.form.getlist("license_selection"))
                if legacy_selection:
                    parsed_form_selections.append(legacy_selection)
                form_license_selections = _merge_license_selections(parsed_form_selections)
                if not form_license_selections:
                    defaults_entry = role_license_defaults.get(role_name) or {}
                    defaults_payload = defaults_entry.get("licenses") or []
                    form_license_selections = _merge_license_selections(
                        LicenseSelection.from_dict(entry) for entry in defaults_payload
                    )
                selected_license_selections = form_license_selections

                job_role = replace(role, user_ou=chosen_ou or role.user_ou)
                ad_groups, azure_groups = _separate_groups(selected_groups)
                app.logger.info(
                    "Onboard: separated groups - selected_count=%s ad_count=%s azure_count=%s ad_groups=%s azure_groups=%s",
                    len(selected_groups),
                    len(ad_groups),
                    len(azure_groups),
                    ad_groups,
                    azure_groups,
                )
                employee = Employee(
                    first_name=first_name,
                    last_name=last_name,
                    username=username,
                    email=email,
                    job_role=role_name,
                    manager_dn=effective_manager,
                    attributes=attributes,
                    groups=ad_groups,
                    licenses=form_license_selections,
                )

                with ADClient(config.ldap) as client:
                    result = client.create_user(employee, job_role, password=password)

                _trigger_sync(config)

                all_assigned_groups = ad_groups + azure_groups
                app.logger.info(
                    "Onboard: groups will be assigned - ad_groups=%s azure_groups=%s",
                    ad_groups,
                    azure_groups,
                )

                try:
                    seed_status = _auto_seed_job_role(
                        config,
                        roles,
                        role_name,
                        user_ou=job_role.user_ou or chosen_ou or config.ldap.user_ou,
                        default_manager_dn=effective_manager,
                        attributes=attributes,
                        groups=all_assigned_groups,
                        licenses=form_license_selections,
                    )
                    if seed_status == "created":
                        flash(f"Saved job role template '{role_name}' for future use.", "info")
                except Exception as exc:  # pragma: no cover - persistence errors should not block onboarding
                    flash(f"User created but job role defaults could not be stored: {exc}", "warning")

                principal_candidates: List[str] = []
                primary_principal = _derive_email(username, email_domain)
                preferred_principal = (primary_principal or email or "").strip()
                if email and email.strip().lower() != preferred_principal.lower():
                    principal_candidates.append(email.strip())
                if primary_principal and primary_principal.strip().lower() != preferred_principal.lower():
                    principal_candidates.append(primary_principal.strip())
                if username:
                    principal_candidates.append(username.strip())

                if form_license_selections:
                    result["licenses"] = [selection.to_dict() for selection in form_license_selections]

                if preferred_principal and form_license_selections:
                    queued_license = _enqueue_license_jobs(
                        app, config, preferred_principal, form_license_selections, alternates=principal_candidates, azure_groups=azure_groups
                    )
                    if queued_license:
                        flash(
                            "Microsoft 365 license and group assignment queued; it will apply shortly.",
                            "info",
                        )
                elif azure_groups and preferred_principal:
                    queued_groups = _enqueue_license_jobs(
                        app, config, preferred_principal, [], alternates=principal_candidates, azure_groups=azure_groups
                    )
                    if queued_groups:
                        flash(
                            "Microsoft 365 group assignment queued; it will apply shortly.",
                            "info",
                        )
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
        job_titles = _preload_job_titles(config, roles)
        return render_template(
            "onboard.html",
            managers=managers,
            ous=ous,
            email_domain=email_domain,
            generated_email=generated_email,
            generated_username=generated_username,
            companies=companies,
            offices=offices,
            selected_groups=selected_groups,
            role_groups=role_groups,
            job_roles=roles,
            job_titles=job_titles,
            role_license_defaults=role_license_defaults,
            selected_license=legacy_selection.sku_id if legacy_selection else "",
            selected_disabled_plans=legacy_selection.disabled_plans if legacy_selection else [],
            selected_license_selections=[selection.to_dict() for selection in selected_license_selections],
            m365_status=m365_status,
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

    @app.get("/api/m365/skus")
    def api_m365_skus() -> Any:
        config = _load_app_config(app)
        payload = _build_m365_status(app, config)
        client = _get_m365_client(app, config)
        if not client:
            payload["items"] = []
            return jsonify(payload)

        refresh_requested = request.args.get("refresh") == "1"
        snapshot: Optional[CatalogSnapshot]
        try:
            snapshot = None
            if refresh_requested:
                snapshot = client.refresh_sku_catalog()
            else:
                snapshot = client.peek_cached_catalog()
                if snapshot is None:
                    snapshot = client.get_sku_catalog(force_refresh=True)
        except M365ClientError as exc:
            payload["error"] = str(exc)
            payload["items"] = []
            return jsonify(payload), 500
        except Exception as exc:
            payload["error"] = str(exc)
            payload["items"] = []
            return jsonify(payload), 500

        if snapshot:
            payload.update(
                {
                    "sku_count": len(snapshot.skus),
                    "fetched_at": snapshot.fetched_at.isoformat(),
                    "stale": snapshot.stale,
                }
            )
            payload["items"] = snapshot.skus
        else:
            payload["items"] = []
        return jsonify(payload)

    @app.post("/api/m365/skus/refresh")
    def api_m365_refresh_skus() -> Any:
        config = _load_app_config(app)
        client = _get_m365_client(app, config)
        if not client:
            payload = _build_m365_status(app, config)
            payload["items"] = []
            return jsonify(payload), 400

        try:
            snapshot = client.refresh_sku_catalog()
        except M365ClientError as exc:
            return jsonify({"message": str(exc)}), 500
        except Exception as exc:
            return jsonify({"message": str(exc)}), 500

        payload = _build_m365_status(app, config)
        payload.update(
            {
                "sku_count": len(snapshot.skus),
                "fetched_at": snapshot.fetched_at.isoformat(),
                "stale": snapshot.stale,
                "items": snapshot.skus,
            }
        )
        return jsonify(payload)

    @app.get("/api/groups")
    def api_groups() -> Any:
        config = _load_app_config(app)
        query = request.args.get("q", "").strip()
        limit = _parse_api_limit(request.args.get("limit"))

        items: List[Dict[str, Any]] = []
        seen: set[str] = set()
        errors: List[str] = []
        guid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

        try:
            with ADClient(config.ldap) as client:
                for group in client.list_groups(query or None, limit):
                    dn = group.get("distinguishedName")
                    if not dn or dn in seen:
                        continue
                    seen.add(dn)
                    items.append(
                        {
                            "name": group.get("name") or _group_display_name(dn),
                            "id": dn,
                            "distinguishedName": dn,
                            "sAMAccountName": group.get("sAMAccountName"),
                            "description": group.get("description"),
                            "source": "ad",
                        }
                    )
        except Exception as exc:
            errors.append(f"AD: {exc}")

        try:
            m365_client = _get_m365_client(app, config)
            if m365_client:
                if query and guid_pattern.match(query):
                    try:
                        group = m365_client.get_group(query)
                        if group and group.get("id") not in seen:
                            seen.add(group["id"])
                            items.append(
                                {
                                    "name": group.get("displayName") or group.get("mailNickname") or query,
                                    "id": group["id"],
                                    "mailNickname": group.get("mailNickname"),
                                    "description": group.get("description"),
                                    "source": "azure",
                                }
                            )
                    except Exception:
                        pass
                azure_groups = m365_client.list_groups(query or None, limit)
                for group in azure_groups:
                    group_id = group.get("id")
                    if not group_id or group_id in seen:
                        continue
                    seen.add(group_id)
                    items.append(
                        {
                            "name": group.get("displayName") or group.get("mailNickname"),
                            "id": group_id,
                            "mailNickname": group.get("mailNickname"),
                            "description": group.get("description"),
                            "source": "azure",
                        }
                    )
        except Exception as exc:
            errors.append(f"Azure: {exc}")

        roles = _load_roles(config)
        lowered = query.lower() if query else None
        for role in roles.values():
            for group_dn in role.groups:
                if not group_dn:
                    continue
                normalized = group_dn.strip()
                if not normalized or normalized in seen:
                    continue
                if lowered and lowered not in normalized.lower():
                    continue
                seen.add(normalized)
                source = "azure" if guid_pattern.match(normalized) else "ad"
                items.append(
                    {
                        "name": _group_display_name(normalized) if source == "ad" else normalized,
                        "id": normalized,
                        "distinguishedName": normalized if source == "ad" else None,
                        "sAMAccountName": None,
                        "description": None,
                        "source": source,
                    }
                )
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break

        payload: Dict[str, Any] = {"items": items[:limit]}
        if errors:
            payload["errors"] = errors
        return jsonify(payload)

    @app.get("/api/roles")
    def api_roles() -> Any:
        config = _load_app_config(app)
        roles = _load_roles(config)
        payload = [_serialize_role(role) for role in roles.values()]
        return jsonify({"items": payload})

    @app.post("/api/roles")
    def api_upsert_role() -> Any:
        data = request.get_json(silent=True) or {}
        name = str(data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "Role name is required."}), 400

        config = _load_app_config(app)
        roles = _load_roles(config)

        original_name = str(data.get("original_name") or "").strip() or None
        if original_name and original_name != name:
            roles.pop(original_name, None)

        description = str(data.get("description") or "").strip() or None
        user_ou = str(data.get("user_ou") or "").strip() or None
        default_manager_dn = str(data.get("default_manager_dn") or "").strip() or None

        attributes_input = data.get("attributes") or ""
        try:
            if isinstance(attributes_input, dict):
                attributes = {
                    str(key).strip(): str(value).strip()
                    for key, value in attributes_input.items()
                    if str(key).strip()
                }
            else:
                attributes = _parse_attributes(str(attributes_input))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        groups_input = data.get("groups") or []
        groups = _dedupe_preserve(str(value).strip() for value in groups_input)

        licenses_input = data.get("licenses") or []
        licenses: List[LicenseSelection] = []
        if isinstance(licenses_input, list):
            for entry in licenses_input:
                try:
                    selection = LicenseSelection.from_dict(entry).normalized()
                    if selection.sku_id:
                        licenses.append(selection)
                except Exception:
                    continue
        else:
            legacy_sku = str(data.get("license_sku_id") or "").strip()
            if legacy_sku:
                disabled_legacy = _dedupe_preserve(
                    str(value).strip() for value in data.get("disabled_service_plans") or []
                )
                licenses.append(
                    LicenseSelection(sku_id=legacy_sku, disabled_plans=disabled_legacy).normalized()
                )

        role = JobRole(
            name=name,
            description=description or None,
            user_ou=user_ou or None,
            default_manager_dn=default_manager_dn or None,
            attributes=attributes,
            groups=groups,
            licenses=licenses,
        )
        roles[name] = role
        save_job_roles(config.storage.job_roles_file, roles)

        return jsonify({"role": _serialize_role(role)})

    @app.delete("/api/roles/<path:role_name>")
    def api_delete_role(role_name: str) -> Any:
        decoded = unquote(role_name)
        config = _load_app_config(app)
        roles = _load_roles(config)
        if decoded not in roles:
            return jsonify({"error": f"Role '{decoded}' not found."}), 404

        roles.pop(decoded, None)
        save_job_roles(config.storage.job_roles_file, roles)
        return ("", 204)

    @app.route("/clone", methods=["GET", "POST"])
    def clone_user() -> str:
        config = _load_app_config(app)
        roles = _load_roles(config)
        managers, ous = _load_directory_context(config)
        companies, offices = _load_reference_values(config)
        role_groups = {name: list(role.groups) for name, role in roles.items()}
        role_license_defaults = {}
        for name, role in roles.items():
            primary = role.primary_license
            role_license_defaults[name] = {
                "license_sku_id": primary.sku_id if primary else None,
                "disabled_service_plans": list(primary.disabled_plans) if primary else [],
                "licenses": [selection.to_dict() for selection in role.licenses],
            }

        query = request.args.get("query", "").strip()
        user_dn = request.args.get("user_dn")
        search_results: List[Dict[str, Any]] = []
        selected_user: Optional[Dict[str, Any]] = None
        template_groups: List[str] = []
        selected_groups = _dedupe_preserve(request.form.getlist("groups"))
        legacy_license_sku = (request.form.get("license_sku") or "").strip()
        legacy_disabled_plans = _dedupe_preserve(request.form.getlist("license_disabled_plan"))
        legacy_selection = (
            LicenseSelection(sku_id=legacy_license_sku, disabled_plans=legacy_disabled_plans).normalized()
            if legacy_license_sku
            else None
        )
        parsed_selections = _parse_license_selections(request.form.getlist("license_selection"))
        if legacy_selection:
            parsed_selections.append(legacy_selection)
        selected_license_selections = _merge_license_selections(parsed_selections)
        primary_selection = selected_license_selections[0] if selected_license_selections else legacy_selection
        selected_license = primary_selection.sku_id if primary_selection else ""
        selected_disabled_plans = list(primary_selection.disabled_plans) if primary_selection else []
        template_license_selection: Optional[Dict[str, Any]] = None
        m365_status = _build_m365_status(app, config)

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
                    template_groups = client.get_user_groups(user_dn)
                    app.logger.info(
                        "Clone template AD groups loaded user_dn=%s group_count=%s",
                        user_dn,
                        len(template_groups or []),
                    )
            except Exception as exc:
                flash(f"Unable to load selected user: {exc}", "error")

            if selected_user and m365_status.get("configured"):
                try:
                    m365_client = _get_m365_client(app, config)
                    if m365_client:
                        lookup = (
                            (selected_user.get("userPrincipalName") or "").strip()
                            or (selected_user.get("mail") or "").strip()
                        )
                        if lookup:
                            graph_user = m365_client.find_user(lookup, select="id")
                            if graph_user:
                                azure_group_ids = m365_client.get_user_groups(graph_user["id"])
                                if azure_group_ids:
                                    ad_group_names = set()
                                    for group_dn in template_groups:
                                        name = _group_display_name(group_dn)
                                        ad_group_names.add(name.lower())
                                    
                                    for group_id in azure_group_ids:
                                        try:
                                            group_details = m365_client.get_group(group_id)
                                            group_name = (group_details.get("displayName") or "").lower()
                                            if group_name not in ad_group_names:
                                                template_groups.append(group_id)
                                        except Exception:
                                            template_groups.append(group_id)
                                    
                                    app.logger.info(
                                        "Clone template Azure groups loaded user=%s azure_group_count=%s",
                                        lookup,
                                        len(azure_group_ids),
                                    )
                except Exception as exc:
                    app.logger.warning("Unable to load Azure groups for template user: %s", exc)

        if selected_user and m365_status.get("configured"):
            try:
                m365_client = _get_m365_client(app, config)
                if m365_client:
                    lookup = (
                        (selected_user.get("userPrincipalName") or "").strip()
                        or (selected_user.get("mail") or "").strip()
                    )
                    graph_user = (
                        m365_client.find_user(
                            lookup,
                            select="id,userPrincipalName,assignedLicenses",
                        )
                        if lookup
                        else None
                    )
                    if graph_user:
                        assigned = [
                            entry
                            for entry in graph_user.get("assignedLicenses", [])
                            if entry.get("skuId")
                        ]
                        if assigned:
                            licenses_payload: List[Dict[str, Any]] = []
                            for entry in assigned:
                                try:
                                    selection = LicenseSelection.from_dict(
                                        {
                                            "sku_id": entry.get("skuId"),
                                            "disabled_plans": list(entry.get("disabledPlans") or []),
                                        }
                                    ).normalized()
                                except Exception:
                                    continue
                                if selection.sku_id:
                                    licenses_payload.append(selection.to_dict())
                            if licenses_payload:
                                primary_dict = licenses_payload[0]
                                template_license_selection = {
                                    "license_sku_id": primary_dict.get("sku_id"),
                                    "disabled_service_plans": list(
                                        primary_dict.get("disabled_plans") or []
                                    ),
                                    "assigned_count": len(licenses_payload),
                                    "source_principal": graph_user.get("userPrincipalName")
                                    or lookup,
                                    "licenses": licenses_payload,
                                }
            except M365ClientError as exc:
                flash(
                    f"Unable to read Microsoft 365 licenses for the template user: {exc}",
                    "warning",
                )
            except Exception as exc:
                flash(f"Unexpected Microsoft 365 license error: {exc}", "warning")

        if not selected_license_selections and template_license_selection:
            template_entries = template_license_selection.get("licenses") or []
            if template_entries:
                selected_license_selections = _merge_license_selections(
                    LicenseSelection.from_dict(entry) for entry in template_entries
                )
        if not selected_license_selections and template_license_selection:
            fallback_sku = template_license_selection.get("license_sku_id")
            if fallback_sku:
                selected_license_selections = _merge_license_selections(
                    [
                        LicenseSelection(
                            sku_id=str(fallback_sku),
                            disabled_plans=template_license_selection.get("disabled_service_plans") or [],
                        )
                    ]
                )
        primary_selection = selected_license_selections[0] if selected_license_selections else None
        selected_license = primary_selection.sku_id if primary_selection else ""
        selected_disabled_plans = list(primary_selection.disabled_plans) if primary_selection else []

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
        if not selected_groups and template_groups:
            selected_groups = _dedupe_preserve(template_groups)
            selected_groups, skipped_defaults = _filter_assignable_groups(selected_groups, config)
            if skipped_defaults:
                flash(
                    "Template user has groups outside the managed scope: "
                    + ", ".join(skipped_defaults),
                    "warning",
                )
            app.logger.info(
                "Clone template group selection user_dn=%s selected_count=%s skipped_count=%s",
                user_dn,
                len(selected_groups),
                len(skipped_defaults),
            )

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
                password = request.form.get("password", "").strip()
                manager_search = request.form.get("manager_search", "").strip()
                explicit_manager_dn = request.form.get("manager_dn") or None
                chosen_ou = request.form.get("user_ou") or None
                telephone_number = request.form.get("telephone_number", "").strip()
                mobile_number = request.form.get("mobile_number", "").strip()
                company_name = request.form.get("company", "").strip()
                office_name = request.form.get("office", "").strip()
                attributes = _parse_attributes(request.form.get("attributes", ""))
                selected_groups = _dedupe_preserve(request.form.getlist("groups"))

                parsed_form_selections = _parse_license_selections(request.form.getlist("license_selection"))
                legacy_license_sku = (request.form.get("license_sku") or "").strip()
                legacy_disabled_plans = _dedupe_preserve(request.form.getlist("license_disabled_plan"))
                legacy_form_selection = (
                    LicenseSelection(sku_id=legacy_license_sku, disabled_plans=legacy_disabled_plans).normalized()
                    if legacy_license_sku
                    else None
                )
                if legacy_form_selection:
                    parsed_form_selections.append(legacy_form_selection)
                form_license_selections = _merge_license_selections(parsed_form_selections)
                if not form_license_selections:
                    defaults_entry = role_license_defaults.get(role_name) or {}
                    defaults_payload: List[Dict[str, Any]] = defaults_entry.get("licenses") or []
                    if not defaults_payload and template_license_selection:
                        defaults_payload = template_license_selection.get("licenses") or []
                    form_license_selections = _merge_license_selections(
                        LicenseSelection.from_dict(entry) for entry in defaults_payload
                    )
                selected_license_selections = form_license_selections
                primary_selection = selected_license_selections[0] if selected_license_selections else None
                selected_license = primary_selection.sku_id if primary_selection else ""
                selected_disabled_plans = list(primary_selection.disabled_plans) if primary_selection else []

                if not all([first_name, last_name, username, email, role_name]):
                    raise ValueError("All fields except attributes are required.")
                if not password:
                    raise ValueError("A temporary password is required.")

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

                ad_groups, azure_groups = _separate_groups(selected_groups)
                app.logger.info(
                    "Clone: separated groups - selected_count=%s ad_count=%s azure_count=%s ad_groups=%s azure_groups=%s",
                    len(selected_groups),
                    len(ad_groups),
                    len(azure_groups),
                    ad_groups,
                    azure_groups,
                )
                employee = Employee(
                    first_name=first_name,
                    last_name=last_name,
                    username=username,
                    email=email,
                    job_role=role_name,
                    manager_dn=manager_dn,
                    attributes=attributes,
                    groups=ad_groups,
                    licenses=form_license_selections,
                )

                chosen_ou = chosen_ou or role.user_ou
                job_role = replace(role, user_ou=chosen_ou or role.user_ou)

                with ADClient(config.ldap) as client:
                    result = client.create_user(employee, job_role, password=password)

                _trigger_sync(config)

                all_assigned_groups = ad_groups + azure_groups
                app.logger.info(
                    "Clone: groups will be assigned - ad_groups=%s azure_groups=%s",
                    ad_groups,
                    azure_groups,
                )

                try:
                    seed_status = _auto_seed_job_role(
                        config,
                        roles,
                        role_name,
                        user_ou=job_role.user_ou or chosen_ou or config.ldap.user_ou,
                        default_manager_dn=manager_dn,
                        attributes=attributes,
                        groups=all_assigned_groups,
                        licenses=form_license_selections,
                    )
                    if seed_status == "created":
                        flash(f"Saved job role template '{role_name}' for future use.", "info")
                except Exception as exc:  # pragma: no cover - persistence errors should not block cloning
                    flash(f"Account cloned but job role defaults could not be stored: {exc}", "warning")

                if primary_selection:
                    result["license_sku_id"] = primary_selection.sku_id
                    result["disabled_service_plans"] = list(primary_selection.disabled_plans)
                if form_license_selections:
                    result["licenses"] = [selection.to_dict() for selection in form_license_selections]

                principal_candidates: List[str] = []
                primary_principal = _derive_email(username, email_domain)
                preferred_principal = (primary_principal or email or "").strip()
                if email and email.strip().lower() != preferred_principal.lower():
                    principal_candidates.append(email.strip())
                if primary_principal and primary_principal.strip().lower() != preferred_principal.lower():
                    principal_candidates.append(primary_principal.strip())
                if username:
                    principal_candidates.append(username.strip())

                queued_license = False
                if preferred_principal and form_license_selections:
                    queued_license = _enqueue_license_jobs(
                        app,
                        config,
                        preferred_principal,
                        form_license_selections,
                        alternates=principal_candidates,
                        azure_groups=azure_groups,
                    )
                    if queued_license:
                        flash(
                            "Microsoft 365 license and group assignment queued; it will apply shortly.",
                            "info",
                        )
                elif azure_groups and preferred_principal:
                    queued_groups = _enqueue_license_jobs(
                        app,
                        config,
                        preferred_principal,
                        [],
                        alternates=principal_candidates,
                        azure_groups=azure_groups,
                    )
                    if queued_groups:
                        flash(
                            "Microsoft 365 group assignment queued; it will apply shortly.",
                            "info",
                        )
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
        prefilled_job_role = request.form.get("job_role")
        if not prefilled_job_role and selected_user:
            prefilled_job_role = (selected_user.get("title") or "").strip()

        job_titles = _preload_job_titles(config, roles)
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
            prefilled_job_role=prefilled_job_role,
            selected_groups=selected_groups,
            role_groups=role_groups,
            role_license_defaults=role_license_defaults,
            selected_license=selected_license,
            selected_disabled_plans=selected_disabled_plans,
            selected_license_selections=[selection.to_dict() for selection in selected_license_selections],
            template_license_selection=template_license_selection,
            m365_status=m365_status,
            job_roles=roles,
            job_titles=job_titles,
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
            action = request.form.get("action", "delete")
            if not user_dn:
                flash("Select a user to process.", "error")
            elif action == "offboard":
                try:
                    user_info = None
                    with ADClient(config.ldap) as client:
                        user_info = client.get_user(user_dn, attributes=["displayName", "mail", "userPrincipalName", "sAMAccountName", "manager"])
                        deleted = client.delete_user(user_dn)
                    if not deleted:
                        raise RuntimeError("User was not deleted from AD.")
                    
                    _trigger_sync(config)
                    
                    if config.m365.has_credentials and user_info:
                        flash(f"Offboarding started for {user_info.get('displayName')}. This process will take several minutes to complete in the background.", "info")
                        threading.Thread(
                            target=_offboard_m365_user_background,
                            args=(app, config, user_info),
                            daemon=True
                        ).start()
                    else:
                        flash("User offboarded from AD. M365 integration not configured.", "success")
                    
                    return redirect(url_for("delete_user"))
                except Exception as exc:
                    flash(f"Unable to offboard user: {exc}", "error")
            else:
                try:
                    with ADClient(config.ldap) as client:
                        deleted = client.delete_user(user_dn)
                    if not deleted:
                        raise RuntimeError("User was not deleted.")
                    _trigger_sync(config)
                    flash(f"Permanently deleted {user_dn} and triggered sync.", "success")
                    return redirect(url_for("delete_user"))
                except Exception as exc:
                    flash(f"Unable to delete user: {exc}", "error")

        return render_template(
            "delete.html",
            query=query,
            search_results=search_results,
        )


def _get_m365_client(app: Flask, config: AppConfig) -> Optional[M365Client]:
    m365_config = getattr(config, "m365", None)
    if not m365_config or not m365_config.has_credentials:
        return None

    signature: Tuple[Any, ...] = (
        m365_config.tenant_id,
        m365_config.client_id,
        m365_config.client_secret,
        str(m365_config.sku_cache_file),
        m365_config.cache_ttl_minutes,
    )
    cached_signature = app.config.get("_M365_CONFIG_SIGNATURE")
    cached_client = app.config.get("_M365_CLIENT")
    if cached_client and cached_signature == signature:
        return cached_client

    try:
        client = M365Client(m365_config)
    except M365ConfigurationError:
        return None

    app.config["_M365_CLIENT"] = client
    app.config["_M365_CONFIG_SIGNATURE"] = signature
    return client


def _build_m365_status(app: Flask, config: AppConfig) -> Dict[str, Any]:
    m365_config = getattr(config, "m365", M365Config())
    status: Dict[str, Any] = {
        "configured": bool(m365_config.has_credentials),
        "sku_count": 0,
        "fetched_at": None,
        "stale": False,
        "error": None,
        "message": "Microsoft 365 integration is not configured.",
        "cache_path": str(m365_config.sku_cache_file),
        "cache_ttl_minutes": m365_config.cache_ttl_minutes,
        "has_secret": bool(m365_config.client_secret),
    }

    if not m365_config.has_credentials:
        return status

    status["message"] = "Microsoft 365 credentials saved. Refresh the catalog to load available licenses."

    try:
        client = _get_m365_client(app, config)
        if not client:
            status["error"] = "Unable to initialise Microsoft 365 client."
            return status

        snapshot = client.peek_cached_catalog()
        if snapshot:
            status["sku_count"] = len(snapshot.skus)
            status["fetched_at"] = snapshot.fetched_at.isoformat()
            status["stale"] = snapshot.stale
            if snapshot.stale:
                status["message"] = "License catalog cached but older than the configured TTL."
            else:
                status["message"] = "License catalog cached."
        else:
            status["message"] = "No license catalog cached yet. Refresh to fetch licenses from Microsoft 365."
    except M365ClientError as exc:
        status["error"] = str(exc)
    except Exception as exc:
        status["error"] = str(exc)

    return status


def _load_app_config(app: Flask) -> AppConfig:
    if has_request_context():
        cached = getattr(g, "_app_config", None)
        if cached is None:
            cached = load_config(app.config.get("CONFIG_PATH"))
            g._app_config = cached
        return cached
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


def _build_msal_client(auth_config: AuthConfig) -> msal.ConfidentialClientApplication:
    authority = f"https://login.microsoftonline.com/{auth_config.tenant_id or 'common'}"
    return msal.ConfidentialClientApplication(
        client_id=auth_config.client_id,
        client_credential=auth_config.client_secret,
        authority=authority,
    )


def _auth_redirect_uri(auth_config: AuthConfig) -> str:
    if auth_config.redirect_uri:
        return auth_config.redirect_uri
    base = request.url_root.rstrip("/")
    return f"{base}{url_for('auth_callback')}"


def _extract_user_groups(
    claims: Dict[str, Any],
    token_result: Dict[str, Any],
    logger: Any,
) -> set[str]:
    groups = set(claims.get("groups") or [])
    if groups:
        logger.info("Auth groups: using %s identifiers from ID token claim.", len(groups))
        return groups

    claim_names = claims.get("_claim_names") or {}
    if claim_names.get("groups"):
        access_token = token_result.get("access_token")
        if access_token:
            try:
                logger.info(
                    "Auth groups: token contained overage reference; fetching from Graph for oid=%s",
                    claims.get("oid"),
                )
                fetched = _fetch_member_groups(access_token, logger)
                logger.info(
                    "Auth groups: Graph lookup for oid=%s returned %s groups.",
                    claims.get("oid"),
                    len(fetched),
                )
                return fetched
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("Unable to fetch group membership from Graph: %s", exc)
        else:
            logger.warning("Auth groups: groups claim present but no access token available.")
    else:
        logger.info("Auth groups: no groups claim or overage reference found in ID token.")
    return groups


def _fetch_member_groups(access_token: str, logger: Any) -> set[str]:
    endpoint = "https://graph.microsoft.com/v1.0/me/memberOf?$select=id"
    headers = {"Authorization": f"Bearer {access_token}"}
    groups: set[str] = set()
    url = endpoint
    while url:
        logger.info("Auth groups: calling Graph memberOf endpoint url=%s", url)
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            logger.warning(
                "Auth groups: Graph memberOf request failed (status=%s body=%s)",
                response.status_code,
                response.text,
            )
            break
        payload = response.json()
        for entry in payload.get("value", []):
            group_id = entry.get("id")
            if group_id:
                groups.add(group_id)
        url = payload.get("@odata.nextLink")
    logger.info("Auth groups: Graph memberOf returned %s unique groups.", len(groups))
    return groups


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


def _parse_api_limit(raw: Optional[str], default: int = 200, maximum: int = 500) -> int:
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
    def _format_part(raw: str) -> str:
        slug = _slugify_name(raw)
        if not slug:
            return ""
        return slug[0].upper() + slug[1:]

    parts = [_format_part(first_name), _format_part(last_name)]
    filtered = [part for part in parts if part]
    if not filtered:
        return ""
    if len(filtered) == 1:
        return filtered[0]
    return ".".join(filtered)


def _serialize_role(role: JobRole) -> Dict[str, Any]:
    licenses_payload = [selection.to_dict() for selection in getattr(role, "licenses", [])]
    primary = getattr(role, "primary_license", None)
    response: Dict[str, Any] = {
        "name": role.name,
        "description": role.description,
        "user_ou": role.user_ou,
        "default_manager_dn": role.default_manager_dn,
        "attributes": dict(role.attributes),
        "groups": list(role.groups),
        "licenses": licenses_payload,
    }
    # Retain backwards-compatible fields so existing UI/JS can continue to read them.
    response["license_sku_id"] = getattr(role, "license_sku_id", None)
    disabled = getattr(role, "disabled_service_plans", [])
    response["disabled_service_plans"] = list(disabled or [])
    return response


def _dedupe_preserve(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        if not value:
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _filter_assignable_groups(groups: Iterable[str], config: AppConfig) -> Tuple[List[str], List[str]]:
    normalized = _dedupe_preserve((group or "").strip() for group in groups)
    base = (config.ldap.group_search_base or "").lower()
    if not base:
        return normalized, []

    guid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
    assignable: List[str] = []
    skipped: List[str] = []
    for group_dn in normalized:
        if guid_pattern.match(group_dn) or group_dn.lower().endswith(base):
            assignable.append(group_dn)
        else:
            skipped.append(group_dn)
    return assignable, skipped


def _group_display_name(distinguished_name: str) -> str:
    match = re.match(r"CN=([^,]+)", distinguished_name, re.IGNORECASE)
    return match.group(1) if match else distinguished_name


def _preload_job_titles(
    config: AppConfig,
    roles: Dict[str, JobRole],
    limit: int = 500,
) -> List[str]:
    titles: set[str] = {name for name in roles if name}
    try:
        with ADClient(config.ldap) as client:
            for title in client.list_job_titles(None, limit):
                cleaned = (title or "").strip()
                if cleaned:
                    titles.add(cleaned)
    except Exception:
        pass
    return sorted(titles, key=str.casefold)


def _extract_role_attribute_defaults(role_name: str, attributes: Dict[str, Any]) -> Dict[str, str]:
    """Select attribute keys that make sense as job role defaults."""

    defaults: Dict[str, str] = {}
    keys = ("title", "department", "company", "physicalDeliveryOfficeName")
    for key in keys:
        value = attributes.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            cleaned = value.strip()
        else:
            cleaned = str(value).strip()
        if cleaned:
            defaults[key] = cleaned
    if role_name and "title" not in defaults:
        defaults["title"] = role_name
    return defaults


def _auto_seed_job_role(
    config: AppConfig,
    roles: Dict[str, JobRole],
    role_name: str,
    *,
    user_ou: Optional[str],
    default_manager_dn: Optional[str],
    attributes: Dict[str, Any],
    groups: Iterable[str],
    licenses: Iterable[LicenseSelection],
) -> Optional[str]:
    """Persist a job role template based on the submitted onboarding data."""

    normalized_name = (role_name or "").strip()
    if not normalized_name:
        return None

    role_ou = (user_ou or "").strip() or (config.ldap.user_ou or None)
    role_manager = (default_manager_dn or "").strip() or None
    role_groups = _dedupe_preserve(groups or [])
    role_licenses = _merge_license_selections(licenses or [])
    role_attributes = _extract_role_attribute_defaults(normalized_name, attributes or {})

    existing = roles.get(normalized_name)
    created = False
    changed = False

    if existing is None:
        roles[normalized_name] = JobRole(
            name=normalized_name,
            description=None,
            user_ou=role_ou,
            default_manager_dn=role_manager,
            attributes=role_attributes,
            groups=role_groups,
            licenses=role_licenses,
        )
        created = True
        changed = True
    else:
        updates: Dict[str, Any] = {}
        if role_ou and not existing.user_ou:
            updates["user_ou"] = role_ou
        if role_manager and not existing.default_manager_dn:
            updates["default_manager_dn"] = role_manager
        if role_groups and not existing.groups:
            updates["groups"] = role_groups
        if role_licenses and not existing.licenses:
            updates["licenses"] = role_licenses
        merged_attributes = dict(existing.attributes)
        attr_changed = False
        for key, value in role_attributes.items():
            if key not in merged_attributes or not str(merged_attributes[key]).strip():
                merged_attributes[key] = value
                attr_changed = True
        if attr_changed:
            updates["attributes"] = merged_attributes

        if updates:
            roles[normalized_name] = replace(existing, **updates)
            changed = True

    if changed:
        save_job_roles(config.storage.job_roles_file, roles)
        return "created" if created else "updated"
    return None


def _get_license_store(app: Flask, config: AppConfig) -> LicenseJobStore:
    store = app.config.get("_LICENSE_JOB_STORE")
    path = config.storage.license_jobs_file
    if store is None or getattr(store, "path", None) != path:
        store = LicenseJobStore(path, max_attempts=5)
        app.config["_LICENSE_JOB_STORE"] = store
    return store


def _ensure_license_worker(app: Flask) -> None:
    if app.config.get("_LICENSE_WORKER_THREAD"):
        return
    if os.environ.get("WERKZEUG_RUN_MAIN") == "false":
        return
    worker = threading.Thread(
        target=_license_worker_loop,
        args=(app,),
        name="license-worker",
        daemon=True,
    )
    worker.start()
    app.config["_LICENSE_WORKER_THREAD"] = worker


def _license_worker_loop(app: Flask) -> None:
    while True:
        time.sleep(_LICENSE_WORKER_INTERVAL)
        try:
            with app.app_context():
                config = _load_app_config(app)
                if not config.m365.has_credentials:
                    continue
                store = _get_license_store(app, config)
                pending_jobs = store.pending_jobs()
                if not pending_jobs:
                    continue
                client = _get_m365_client(app, config)
                if not client:
                    continue
                for job in pending_jobs:
                    _process_license_job(app, config, store, client, job)
        except Exception as exc:  # pragma: no cover - worker resilience
            app.logger.exception("License worker encountered an error: %s", exc)


def _process_license_job(
    app: Flask,
    config: AppConfig,
    store: LicenseJobStore,
    client: M365Client,
    job: LicenseJob,
) -> None:
    print(f"\n{'='*80}")
    print(f"PROCESSING LICENSE JOB: {job.id}")
    print(f"  Principal: {job.principal}")
    print(f"  SKU ID: {job.sku_id or '(none - groups only)'}")
    print(f"  Azure Groups: {len(job.azure_groups)} groups")
    print(f"  Attempt: {job.attempts + 1}")
    print(f"{'='*80}\n")
    app.logger.info(
        "Processing license job: principal=%s sku_id=%s azure_groups=%s attempts=%s",
        job.principal,
        job.sku_id or "(none)",
        job.azure_groups,
        job.attempts,
    )
    retry_index = min(job.attempts, len(_LICENSE_RETRY_SCHEDULE) - 1)
    retry_delay = timedelta(seconds=_LICENSE_RETRY_SCHEDULE[retry_index])

    print("Looking up user in Microsoft 365...")
    lookup_candidates = [job.principal] + [candidate for candidate in job.principal_candidates if candidate]
    print(f"  Candidates: {lookup_candidates}")
    graph_user: Optional[Dict[str, Any]] = None
    chosen_lookup: Optional[str] = None
    for candidate in lookup_candidates:
        if not candidate:
            continue
        chosen_lookup = candidate
        print(f"  Trying: {candidate}")
        try:
            graph_user = client.find_user(candidate, select="id,userPrincipalName,usageLocation")
        except M365ClientError as exc:
            print(f"  ERROR: M365 lookup failed: {exc}")
            store.defer_job(job.id, retry_delay, str(exc))
            app.logger.warning("Microsoft 365 lookup failed for %s: %s", candidate, exc)
            return
        except Exception as exc:
            print(f"  ERROR: Unexpected lookup error: {exc}")
            store.defer_job(job.id, retry_delay, str(exc))
            app.logger.exception("Unexpected error looking up %s: %s", candidate, exc)
            return
        if graph_user and graph_user.get("id"):
            print(f"  FOUND: {graph_user.get('userPrincipalName')} (ID: {graph_user.get('id')})")
            if candidate != job.principal:
                job.principal = candidate
                job.principal_candidates = [
                    value for value in job.principal_candidates if value != candidate
                ]
                store.reset_from_copy(job)
            break
    else:
        chosen_lookup = job.principal
        print(f"  NOT FOUND: User not yet synced to Microsoft 365")
        store.defer_job(job.id, retry_delay, "User not yet available in Microsoft 365.")
        app.logger.info(
            "License assignment deferred for %s; user not found.",
            chosen_lookup or "<unknown>",
        )
        return

    lookup = chosen_lookup or job.principal
    user_id = graph_user["id"]
    
    usage_location = str(graph_user.get("usageLocation") or "").strip()
    default_usage_location = str(config.m365.default_usage_location or "").strip()
    
    if not usage_location or len(usage_location) != 2:
        if not default_usage_location:
            store.defer_job(
                job.id,
                retry_delay,
                "User missing valid usage location; configure m365.default_usage_location.",
            )
            app.logger.warning(
                "Microsoft 365 job deferred for %s: usageLocation missing/invalid and no default configured.",
                lookup,
            )
            return
        print(f"\nSetting usage location to {default_usage_location}...")
        try:
            client.update_user(user_id, usageLocation=default_usage_location)
            usage_location = default_usage_location
            print(f"  SUCCESS: Set usageLocation={default_usage_location}")
            print(f"  Waiting 30 seconds for Azure to process...")
            app.logger.info(
                "Set usageLocation=%s for %s prior to license/group assignment.",
                default_usage_location,
                lookup,
            )
            time.sleep(30)
        except M365ClientError as exc:
            print(f"  FAILED: {exc}")
            if "does not exist" in str(exc).lower() or "not found" in str(exc).lower():
                store.defer_job(job.id, retry_delay, f"Unable to set usageLocation: {exc}")
                app.logger.warning(
                    "Microsoft 365 usageLocation update deferred for %s: %s",
                    lookup,
                    exc,
                )
                return
            app.logger.warning(
                "Microsoft 365 usageLocation update failed for %s (continuing anyway): %s",
                lookup,
                exc,
            )
        except Exception as exc:
            print(f"  UNEXPECTED ERROR: {exc}")
            app.logger.warning(
                "Unexpected error setting usageLocation for %s (continuing anyway): %s", lookup, exc
            )

    if job.sku_id:
        print(f"\nAssigning license {job.sku_id}...")
        print(f"  User ID: {user_id}")
        print(f"  Usage Location: {usage_location}")
        print(f"  Disabled plans: {job.disabled_plans}")
        
        base_skus = {
            "05e9a617-0261-4cee-bb44-138d3ef5d965",
            "c5928f49-12ba-48f7-ada3-0d743a3601d5",
            "6fd2c87f-b296-42f0-b197-1e91e994b900",
            "f30db892-07e9-47e9-837c-80727f46fd3d",
            "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",
            "ac5cef5d-921b-4f97-9ef3-c99076e5470f",
            "4b590615-0888-425a-a965-b3bf7789848d",
            "66b55226-6b4f-492c-910c-a3b7a3c9d993",
            "18181a46-0d4e-45cd-891e-60aabd171b4e",
            "1392051d-0cb9-4b7a-88d5-621fee5e8711",
            "4b585984-651b-448a-9e53-3b10f069cf7f",
            "53818b1b-4a27-454b-8896-0dba576410e6",
            "09015f9f-377f-4538-bbb5-f75ceb09358a",
        }
        is_base_license = job.sku_id.lower() in {s.lower() for s in base_skus}
        
        try:
            app.logger.info("Attempting to assign license %s to %s (user_id=%s)", job.sku_id, lookup, user_id)
            client.assign_license(user_id, job.sku_id, job.disabled_plans)
            print(f"  SUCCESS: License {job.sku_id} assigned")
            app.logger.info("Successfully assigned Microsoft 365 license %s to %s.", job.sku_id, lookup)
            
            if is_base_license:
                print(f"  Waiting 30 seconds for Exchange mailbox provisioning...")
                time.sleep(30)
            else:
                time.sleep(5)
        except M365ClientError as exc:
            error_msg = str(exc)
            status_code = getattr(exc, "status_code", 0)
            print(f"  FAILED: Status {status_code} - {error_msg}")
            
            if status_code == 400:
                if "depends on the service plan" in error_msg.lower() and not is_base_license:
                    print(f"  DEFERRING: Dependency error, will retry after base license provisions")
                    store.defer_job(job.id, timedelta(seconds=60), error_msg)
                    app.logger.warning(
                        "Microsoft 365 license assignment deferred for %s (%s): dependency error, retrying",
                        lookup,
                        job.sku_id,
                    )
                    return
                
                store.mark_completed(job.id)
                print(f"  MARKING AS COMPLETE (400 error - will not retry)")
                app.logger.error(
                    "Microsoft 365 license assignment FAILED (400) for %s (%s): %s - marked complete",
                    lookup,
                    job.sku_id,
                    exc,
                )
                return
            
            print(f"  DEFERRING: Will retry in {retry_delay.total_seconds()}s")
            store.defer_job(job.id, retry_delay, error_msg)
            app.logger.warning(
                "Microsoft 365 assignLicense deferred for %s (%s): %s",
                lookup,
                job.sku_id,
                exc,
            )
            return
        except Exception as exc:
            print(f"  UNEXPECTED ERROR: {exc}")
            store.defer_job(job.id, retry_delay, str(exc))
            app.logger.exception(
                "Unexpected error assigning license %s to %s: %s", job.sku_id, lookup, exc
            )
            return

    if job.azure_groups:
        print(f"\nProcessing {len(job.azure_groups)} Azure groups...")
        app.logger.info(
            "Processing %s Azure groups for %s (user_id=%s)",
            len(job.azure_groups),
            lookup,
            user_id,
        )
        for idx, group_id in enumerate(job.azure_groups, 1):
            print(f"\n  Group {idx}/{len(job.azure_groups)}: {group_id}")
            try:
                group_details = client.get_group(group_id)
                group_name = group_details.get("displayName") or group_id
                on_prem_synced = group_details.get("onPremisesSyncEnabled")
                mail_enabled = group_details.get("mailEnabled")
                security_enabled = group_details.get("securityEnabled")
                group_types = group_details.get("groupTypes") or []
                membership_rule = group_details.get("membershipRule")
                
                print(f"    Name: {group_name}")
                print(f"    OnPremSync: {on_prem_synced}, Mail: {mail_enabled}, Security: {security_enabled}")
                print(f"    Types: {group_types}, Dynamic: {bool(membership_rule)}")
                
                if on_prem_synced:
                    print(f"    SKIPPED: On-premises synced (managed in AD)")
                    app.logger.warning(
                        "SKIPPED: On-premises synced group %s (%s) - must be managed in AD",
                        group_name,
                        group_id,
                    )
                    continue
                
                if membership_rule or "DynamicMembership" in group_types:
                    print(f"    SKIPPED: Dynamic group (rule-based membership)")
                    app.logger.warning(
                        "SKIPPED: Dynamic group %s (%s) - membership is rule-based",
                        group_name,
                        group_id,
                    )
                    continue
                
                is_distribution_list = mail_enabled and not security_enabled and "Unified" not in group_types
                if is_distribution_list:
                    if config.m365.has_exo_credentials:
                        print(f"    Adding to Distribution List via Exchange Online...")
                        try:
                            _add_to_distribution_list(app, config, lookup, group_id)
                            print(f"    SUCCESS: Added to DL {group_name}")
                            app.logger.info("Added %s to distribution list %s via Exchange Online.", lookup, group_name)
                        except Exception as dl_exc:
                            print(f"    FAILED: {dl_exc}")
                            app.logger.error("Failed to add %s to DL %s: %s", lookup, group_name, dl_exc)
                    else:
                        print(f"    SKIPPED: Distribution list (Exchange Online not configured)")
                        app.logger.warning(
                            "SKIPPED: Distribution list %s (%s) - Exchange Online credentials not configured",
                            group_name,
                            group_id,
                        )
                    continue
                
                print(f"    Adding user to group...")
                client.add_user_to_group(user_id, group_id)
                print(f"    SUCCESS: Added to {group_name}")
                app.logger.info("Successfully added %s to Azure group %s (%s).", lookup, group_name, group_id)
            except M365ClientError as exc:
                print(f"    FAILED: {exc}")
                app.logger.error(
                    "FAILED to add %s to Azure group %s: %s",
                    lookup,
                    group_id,
                    exc,
                )
            except Exception as exc:
                print(f"    UNEXPECTED ERROR: {exc}")
                app.logger.exception(
                    "Unexpected error adding %s to Azure group %s: %s",
                    lookup,
                    group_id,
                    exc,
                )

    print(f"\nJOB COMPLETED: {job.id}\n")
    store.mark_completed(job.id)


def _enqueue_license_job(
    app: Flask,
    config: AppConfig,
    principal: Optional[str],
    sku_id: Optional[str],
    disabled_plans: Iterable[str],
    alternates: Optional[Iterable[str]] = None,
    azure_groups: Optional[Iterable[str]] = None,
) -> bool:
    if not principal:
        return False
    if not sku_id and not azure_groups:
        return False
    if not config.m365.has_credentials:
        app.logger.info(
            "Skipping Microsoft 365 license queue for %s; credentials not configured.",
            principal,
        )
        return False
    try:
        store = _get_license_store(app, config)
        store.add_job(
            principal=principal,
            sku_id=sku_id,
            disabled_plans=disabled_plans,
            alternates=alternates or [],
            azure_groups=azure_groups or [],
            delay_seconds=_LICENSE_INITIAL_DELAY_SECONDS,
        )
        app.logger.info("Queued Microsoft 365 license assignment for %s (%s).", principal, sku_id)
        return True
    except Exception as exc:
        app.logger.exception("Unable to queue Microsoft 365 license job for %s: %s", principal, exc)
        return False


def _enqueue_license_jobs(
    app: Flask,
    config: AppConfig,
    principal: Optional[str],
    selections: Iterable[LicenseSelection],
    alternates: Optional[Iterable[str]] = None,
    azure_groups: Optional[Iterable[str]] = None,
) -> bool:
    queued_any = False
    merged = _merge_license_selections(selections)
    
    print(f"\n=== LICENSE QUEUEING ===")
    print(f"Principal: {principal}")
    print(f"Total licenses to queue: {len(merged)}")
    for idx, sel in enumerate(merged, 1):
        print(f"  {idx}. SKU: {sel.sku_id}, Disabled plans: {len(sel.disabled_plans)}")
    
    base_skus = {
        "05e9a617-0261-4cee-bb44-138d3ef5d965",  # M365 E3
        "c5928f49-12ba-48f7-ada3-0d743a3601d5",  # Visio Plan 2
        "6fd2c87f-b296-42f0-b197-1e91e994b900",  # M365 E5
        "f30db892-07e9-47e9-837c-80727f46fd3d",  # M365 Business Premium
        "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",  # M365 Business Basic
        "ac5cef5d-921b-4f97-9ef3-c99076e5470f",  # M365 Business Standard
        "4b590615-0888-425a-a965-b3bf7789848d",  # M365 F3
        "66b55226-6b4f-492c-910c-a3b7a3c9d993",  # M365 F1
        "18181a46-0d4e-45cd-891e-60aabd171b4e",  # Office 365 E1
        "1392051d-0cb9-4b7a-88d5-621fee5e8711",  # Office 365 E5
        "4b585984-651b-448a-9e53-3b10f069cf7f",  # Project Plan 1
        "53818b1b-4a27-454b-8896-0dba576410e6",  # Project Plan 3
        "09015f9f-377f-4538-bbb5-f75ceb09358a",  # Project Plan 5
    }
    
    base_selections = []
    addon_selections = []
    
    for selection in merged:
        if selection.sku_id.lower() in {s.lower() for s in base_skus}:
            base_selections.append(selection)
            print(f"  Classified as BASE: {selection.sku_id}")
        else:
            addon_selections.append(selection)
            print(f"  Classified as ADDON: {selection.sku_id}")
    
    print(f"\nQueueing order: {len(base_selections)} base licenses first, then {len(addon_selections)} add-ons")
    
    for idx, selection in enumerate(base_selections, 1):
        print(f"  Queueing BASE {idx}/{len(base_selections)}: {selection.sku_id}")
        queued = _enqueue_license_job(
            app,
            config,
            principal,
            selection.sku_id,
            selection.disabled_plans,
            alternates=alternates,
            azure_groups=[],
        )
        queued_any = queued_any or queued
    
    for idx, selection in enumerate(addon_selections, 1):
        print(f"  Queueing ADDON {idx}/{len(addon_selections)}: {selection.sku_id}")
        queued = _enqueue_license_job(
            app,
            config,
            principal,
            selection.sku_id,
            selection.disabled_plans,
            alternates=alternates,
            azure_groups=[],
        )
        queued_any = queued_any or queued
    
    if azure_groups:
        print(f"  Queueing GROUPS job with {len(azure_groups)} groups")
        queued = _enqueue_license_job(
            app,
            config,
            principal,
            "",
            [],
            alternates=alternates,
            azure_groups=azure_groups,
        )
        queued_any = queued_any or queued
    
    print(f"=== QUEUEING COMPLETE ===\n")
    return queued_any


def _separate_groups(groups: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Separate groups into AD (DN format) and Azure (GUID format) groups."""
    ad_groups: List[str] = []
    azure_groups: List[str] = []
    guid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
    for group in groups:
        if not group:
            continue
        group = group.strip()
        if guid_pattern.match(group):
            azure_groups.append(group)
        else:
            ad_groups.append(group)
    return ad_groups, azure_groups


def _trigger_sync(config: AppConfig) -> None:
    try:
        run_sync_command(config.sync)
    except RuntimeError as exc:
        flash(f"Directory sync reported a problem: {exc}", "error")


def _offboard_m365_user_background(app: Flask, config: AppConfig, user_info: Dict[str, Any]) -> None:
    """Background thread wrapper for M365 offboarding."""
    with app.app_context():
        try:
            _offboard_m365_user(app, config, user_info)
        except Exception as exc:
            app.logger.exception("Background M365 offboarding failed: %s", exc)


def _offboard_m365_user(app: Flask, config: AppConfig, user_info: Dict[str, Any]) -> None:
    """Comprehensive M365 offboarding: restore, assign license, wait for mailbox, convert to shared, remove licenses/groups, block sign-in, rename."""
    import time
    from datetime import datetime
    
    client = _get_m365_client(app, config)
    if not client:
        raise RuntimeError("M365 client not available")
    
    lookup = (user_info.get("userPrincipalName") or user_info.get("mail") or "").strip()
    if not lookup:
        raise RuntimeError("User has no email/UPN for M365 lookup")
    
    app.logger.info("Starting M365 offboarding for %s", lookup)
    print(f"\n=== M365 OFFBOARDING: {lookup} ===")
    print("Waiting 90s for AD sync to complete...")
    time.sleep(90)
    
    print("Looking for user in deleted items...")
    graph_user = None
    user_id = None
    
    try:
        deleted_users = client._request("GET", "/directory/deletedItems/microsoft.graph.user")
        for deleted in deleted_users.get("value", []):
            deleted_upn = (deleted.get("userPrincipalName") or "").lower()
            deleted_mail = (deleted.get("mail") or "").lower()
            lookup_lower = lookup.lower()
            
            if deleted_upn == lookup_lower or deleted_mail == lookup_lower or lookup_lower in deleted_upn:
                user_id = deleted["id"]
                print(f"Found in deleted items: {user_id} (UPN: {deleted.get('userPrincipalName')})")
                print("Restoring user...")
                client.restore_user(user_id)
                print("Waiting for restore to complete...")
                time.sleep(30)
                
                for attempt in range(5):
                    try:
                        graph_user = client.get_user(user_id, select="id,userPrincipalName,displayName,mail,manager")
                        print(f"User restored: {graph_user.get('userPrincipalName')}")
                        break
                    except Exception as get_exc:
                        if attempt < 4:
                            print(f"  Restore not ready, waiting 10s... (attempt {attempt + 1}/5)")
                            time.sleep(10)
                        else:
                            raise
                break
        else:
            raise RuntimeError(f"User {lookup} not found in M365 deleted items after sync")
    except Exception as restore_exc:
        raise RuntimeError(f"Failed to find/restore user: {restore_exc}")
    
    display_name = graph_user.get("displayName", "")
    manager_id = graph_user.get("manager", {}).get("id") if isinstance(graph_user.get("manager"), dict) else None
    manager_email = None
    
    if not manager_id and user_info.get("manager"):
        manager_dn = user_info["manager"]
        try:
            with ADClient(config.ldap) as ad_client:
                manager_info = ad_client.get_user(manager_dn, attributes=["mail", "userPrincipalName"])
                manager_lookup = manager_info.get("userPrincipalName") or manager_info.get("mail")
                if manager_lookup:
                    manager_user = client.find_user(manager_lookup, select="id,mail")
                    if manager_user:
                        manager_id = manager_user["id"]
                        manager_email = manager_user.get("mail")
        except Exception:
            pass
    
    if manager_id and not manager_email:
        try:
            manager_user = client.get_user(manager_id, select="mail")
            manager_email = manager_user.get("mail")
        except Exception:
            pass
    
    print(f"Manager: {manager_email or 'Not found'}")
    
    user_licenses = []
    try:
        current_user = client.get_user(user_id, select="assignedLicenses")
        user_licenses = current_user.get("assignedLicenses", [])
        print(f"User has {len(user_licenses)} licenses")
    except Exception as lic_check_exc:
        print(f"  Could not check licenses: {lic_check_exc}")
    
    if not user_licenses:
        print("No licenses found, assigning temporary E3 license for mailbox access...")
        try:
            if not client.get_user(user_id, select="usageLocation").get("usageLocation"):
                client.update_user(user_id, usageLocation=config.m365.default_usage_location or "US")
                time.sleep(15)
            client.assign_license(user_id, "05e9a617-0261-4cee-bb44-138d3ef5d965", [])
            print("  Assigned E3 license, waiting 120s for mailbox provisioning...")
            time.sleep(120)
        except Exception as temp_lic_exc:
            print(f"  Could not assign temporary license: {temp_lic_exc}")
    else:
        print("Licenses present, waiting 90s for mailbox to be fully ready...")
        time.sleep(90)
    
    print("Checking mailbox status...")
    mailbox_ready = False
    for check_attempt in range(5):
        try:
            result = _check_mailbox_exists(app, config, lookup)
            if result:
                print(f"  Mailbox confirmed ready")
                mailbox_ready = True
                break
        except Exception as check_exc:
            print(f"  Check attempt {check_attempt + 1}/5: {check_exc}")
        if check_attempt < 4:
            print(f"  Waiting 30s before next check...")
            time.sleep(30)
    
    if not mailbox_ready:
        print("  WARNING: Could not confirm mailbox is ready, proceeding anyway...")
    
    if config.m365.has_exo_credentials and manager_email:
        print("Converting mailbox to shared and setting up forwarding...")
        for attempt in range(5):
            try:
                _convert_mailbox_to_shared_and_forward(app, config, lookup, manager_email)
                print("  SUCCESS: Mailbox converted and forwarding enabled")
                break
            except Exception as mb_exc:
                if attempt < 4:
                    print(f"  Attempt {attempt + 1} failed, waiting 45s and retrying...")
                    time.sleep(45)
                else:
                    print(f"  FAILED after 5 attempts: {mb_exc}")
                    app.logger.error("Mailbox conversion failed for %s: %s", lookup, mb_exc)
    else:
        print("Skipping mailbox conversion (Exchange Online not configured or no manager)")
    
    print("Removing all licenses...")
    try:
        client.remove_all_licenses(user_id)
        print("  SUCCESS: All licenses removed")
    except Exception as lic_exc:
        print(f"  FAILED: {lic_exc}")
        app.logger.error("License removal failed for %s: %s", lookup, lic_exc)
    
    print("Removing all group memberships...")
    removed_count = 0
    try:
        group_ids = client.get_user_groups(user_id)
        print(f"  Found {len(group_ids)} groups to process")
        
        for idx, group_id in enumerate(group_ids, 1):
            print(f"\n  Group {idx}/{len(group_ids)}: {group_id}")
            try:
                group_details = client.get_group(group_id)
                group_name = group_details.get("displayName") or group_id
                on_prem_synced = group_details.get("onPremisesSyncEnabled")
                mail_enabled = group_details.get("mailEnabled")
                security_enabled = group_details.get("securityEnabled")
                group_types = group_details.get("groupTypes") or []
                membership_rule = group_details.get("membershipRule")
                
                print(f"    Name: {group_name}")
                print(f"    OnPremSync: {on_prem_synced}, Mail: {mail_enabled}, Security: {security_enabled}")
                print(f"    Types: {group_types}, Dynamic: {bool(membership_rule)}")
                
                if on_prem_synced:
                    print(f"    SKIPPED: On-premises synced (managed in AD)")
                    app.logger.warning(
                        "SKIPPED: On-premises synced group %s (%s) - must be managed in AD",
                        group_name,
                        group_id,
                    )
                    continue
                
                if membership_rule or "DynamicMembership" in group_types:
                    print(f"    SKIPPED: Dynamic group (rule-based membership)")
                    app.logger.warning(
                        "SKIPPED: Dynamic group %s (%s) - membership is rule-based",
                        group_name,
                        group_id,
                    )
                    continue
                
                is_distribution_list = mail_enabled and not security_enabled and "Unified" not in group_types
                if is_distribution_list:
                    if config.m365.has_exo_credentials:
                        print(f"    Removing from Distribution List via Exchange Online...")
                        try:
                            _remove_from_distribution_list(app, config, lookup, group_id)
                            print(f"    SUCCESS: Removed from DL {group_name}")
                            removed_count += 1
                            app.logger.info("Removed %s from distribution list %s via Exchange Online.", lookup, group_name)
                        except Exception as dl_exc:
                            print(f"    FAILED: {dl_exc}")
                            app.logger.error("Failed to remove %s from DL %s: %s", lookup, group_name, dl_exc)
                    else:
                        print(f"    SKIPPED: Distribution list (Exchange Online not configured)")
                        app.logger.warning(
                            "SKIPPED: Distribution list %s (%s) - Exchange Online credentials not configured",
                            group_name,
                            group_id,
                        )
                    continue
                
                print(f"    Removing user from group...")
                client.remove_user_from_group(user_id, group_id)
                print(f"    SUCCESS: Removed from {group_name}")
                removed_count += 1
                app.logger.info("Successfully removed %s from Azure group %s (%s).", lookup, group_name, group_id)
            except M365ClientError as exc:
                print(f"    FAILED: {exc}")
                app.logger.error(
                    "FAILED to remove %s from Azure group %s: %s",
                    lookup,
                    group_id,
                    exc,
                )
            except Exception as exc:
                print(f"    UNEXPECTED ERROR: {exc}")
                app.logger.exception(
                    "Unexpected error removing %s from Azure group %s: %s",
                    lookup,
                    group_id,
                    exc,
                )
        
        print(f"\n  COMPLETE: Removed from {removed_count}/{len(group_ids)} groups")
    except Exception as grp_exc:
        print(f"  FAILED: {grp_exc}")
        app.logger.error("Group removal failed for %s: %s", lookup, grp_exc)
    
    print("Blocking sign-in...")
    try:
        client.block_sign_in(user_id)
        print("  SUCCESS: Sign-in blocked")
    except Exception as block_exc:
        print(f"  FAILED: {block_exc}")
        app.logger.error("Block sign-in failed for %s: %s", lookup, block_exc)
    
    now = datetime.now()
    offboard_date = f"{now.month}.{now.day:02d}.{now.strftime('%y')}"
    new_display_name = f"FE_{display_name} {offboard_date}"
    print(f"Renaming user and clearing all contact/organization info...")
    print(f"  New display name: {new_display_name}")
    try:
        payload = {
            "displayName": new_display_name,
            "givenName": None,
            "surname": None,
            "jobTitle": None,
            "department": None,
            "companyName": None,
            "officeLocation": None,
            "businessPhones": [],
            "mobilePhone": None,
            "faxNumber": None,
            "streetAddress": None,
            "city": None,
            "state": None,
            "postalCode": None,
            "country": None,
        }
        client._request("PATCH", f"/users/{user_id}", json=payload)
        
        # Clear manager reference separately
        try:
            client._request("DELETE", f"/users/{user_id}/manager/$ref")
            print("  SUCCESS: Manager reference cleared")
        except Exception as mgr_exc:
            print(f"  Manager clear failed (may not have had one): {mgr_exc}")
        
        print("  SUCCESS: User renamed and all contact/organization info cleared")
    except Exception as rename_exc:
        print(f"  FAILED: {rename_exc}")
        app.logger.error("Rename/clear failed for %s: %s", lookup, rename_exc)
    
    print(f"=== OFFBOARDING COMPLETE ===")
    app.logger.info("M365 offboarding completed for %s", lookup)


def _check_mailbox_exists(
    app: Flask,
    config: AppConfig,
    user_email: str,
) -> bool:
    """Check if mailbox exists and is ready using Exchange Online PowerShell."""
    ps5_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
    script = f"""$env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$ErrorActionPreference = 'Stop'
try {{
    Connect-ExchangeOnline -AppId '{config.m365.client_id}' -CertificateThumbprint '{config.m365.cert_thumbprint}' -Organization '{config.m365.exo_organization}' -ShowBanner:$false -ErrorAction Stop
    
    $mailbox = Get-Mailbox -Identity '{user_email}' -ErrorAction Stop
    if ($mailbox) {{
        Write-Output 'MAILBOX_EXISTS'
    }}
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}} finally {{
    try {{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }} catch {{}}
}}"""
    
    env = os.environ.copy()
    env.pop('PSModulePath', None)
    
    result = subprocess.run(
        [ps5_path, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    
    return result.returncode == 0 and "MAILBOX_EXISTS" in result.stdout


def _convert_mailbox_to_shared_and_forward(
    app: Flask,
    config: AppConfig,
    user_email: str,
    manager_email: str,
) -> None:
    """Convert mailbox to shared, hide from GAL, and forward to manager using Exchange Online PowerShell."""
    ps5_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
    script = f"""$env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$ErrorActionPreference = 'Stop'
try {{
    Connect-ExchangeOnline -AppId '{config.m365.client_id}' -CertificateThumbprint '{config.m365.cert_thumbprint}' -Organization '{config.m365.exo_organization}' -ShowBanner:$false -ErrorAction Stop
    
    Set-Mailbox -Identity '{user_email}' -Type Shared -ErrorAction Stop
    Set-Mailbox -Identity '{user_email}' -HiddenFromAddressListsEnabled $true -ErrorAction Stop
    Set-Mailbox -Identity '{user_email}' -ForwardingAddress '{manager_email}' -DeliverToMailboxAndForward $false -ErrorAction Stop
    
    Write-Output 'SUCCESS'
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}} finally {{
    try {{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }} catch {{}}
}}"""
    
    env = os.environ.copy()
    env.pop('PSModulePath', None)
    
    result = subprocess.run(
        [ps5_path, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    
    if result.returncode != 0 or "SUCCESS" not in result.stdout:
        error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
        raise RuntimeError(f"Exchange command failed: {error_msg}")


def _add_to_distribution_list(
    app: Flask,
    config: AppConfig,
    user_email: str,
    group_id: str,
) -> None:
    ps5_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
    script = f"""$env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$ErrorActionPreference = 'Stop'
try {{
    Connect-ExchangeOnline -AppId '{config.m365.client_id}' -CertificateThumbprint '{config.m365.cert_thumbprint}' -Organization '{config.m365.exo_organization}' -ShowBanner:$false -ErrorAction Stop
    
    $group = Get-DistributionGroup -Identity '{group_id}' -ErrorAction Stop
    $groupEmail = $group.PrimarySmtpAddress
    
    Add-DistributionGroupMember -Identity $groupEmail -Member '{user_email}' -ErrorAction Stop
    Write-Output 'SUCCESS'
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}} finally {{
    try {{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }} catch {{}}
}}"""
    
    env = os.environ.copy()
    env.pop('PSModulePath', None)
    
    result = subprocess.run(
        [ps5_path, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    
    if result.returncode != 0 or "SUCCESS" not in result.stdout:
        error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
        raise RuntimeError(f"Exchange command failed: {error_msg}")


def _remove_from_distribution_list(
    app: Flask,
    config: AppConfig,
    user_email: str,
    group_id: str,
) -> None:
    """Remove user from Distribution List using Exchange Online PowerShell."""
    ps5_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
    script = f"""$env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$ErrorActionPreference = 'Stop'
try {{
    Connect-ExchangeOnline -AppId '{config.m365.client_id}' -CertificateThumbprint '{config.m365.cert_thumbprint}' -Organization '{config.m365.exo_organization}' -ShowBanner:$false -ErrorAction Stop
    
    $group = Get-DistributionGroup -Identity '{group_id}' -ErrorAction Stop
    $groupEmail = $group.PrimarySmtpAddress
    
    Remove-DistributionGroupMember -Identity $groupEmail -Member '{user_email}' -Confirm:$false -ErrorAction Stop
    Write-Output 'SUCCESS'
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}} finally {{
    try {{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }} catch {{}}
}}"""
    
    env = os.environ.copy()
    env.pop('PSModulePath', None)
    
    result = subprocess.run(
        [ps5_path, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    
    if result.returncode != 0 or "SUCCESS" not in result.stdout:
        error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
        raise RuntimeError(f"Exchange command failed: {error_msg}")





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
