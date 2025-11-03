"""Flask-powered web interface for the onboarding/offboarding toolkit."""
from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, flash, redirect, render_template, request, url_for

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
from .models import Employee, JobRole
from .storage import load_job_roles
from .sync import run_sync_command


_TEMPLATE_FOLDER = Path(__file__).resolve().parent / "templates"
_DEFAULT_ATTRIBUTE_KEYS = ("title", "department", "company", "employeeID")


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

        if request.method == "POST":
            try:
                first_name = request.form.get("first_name", "").strip()
                last_name = request.form.get("last_name", "").strip()
                username = request.form.get("username", "").strip()
                email = request.form.get("email", "").strip()
                role_name = request.form.get("job_role", "")
                password = request.form.get("password", "") or None
                manager_dn = request.form.get("manager_dn") or None
                chosen_ou = request.form.get("user_ou") or None
                attributes = _parse_attributes(request.form.get("attributes", ""))

                if not all([first_name, last_name, username, email, role_name]):
                    raise ValueError("All fields except password and attributes are required.")

                if role_name not in roles:
                    raise ValueError(f"Unknown job role '{role_name}'.")

                role = roles[role_name]
                effective_manager = manager_dn or role.default_manager_dn
                if not effective_manager:
                    raise ValueError("A manager must be selected or defined in the job role.")

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

        return render_template(
            "onboard.html",
            managers=managers,
            ous=ous,
        )

    @app.route("/clone", methods=["GET", "POST"])
    def clone_user() -> str:
        config = _load_app_config(app)
        roles = _load_roles(config)
        managers, ous = _load_directory_context(config)

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
                        attributes=["manager", "title", "department", "company", "mail"],
                    )
            except Exception as exc:
                flash(f"Unable to load selected user: {exc}", "error")

        if request.method == "POST":
            try:
                role_name = request.form.get("job_role", "")
                if role_name not in roles:
                    raise ValueError("Select a valid job role to clone into.")

                attributes = _parse_attributes(request.form.get("attributes", ""))
                manager_dn = request.form.get("manager_dn") or roles[role_name].default_manager_dn
                if not manager_dn:
                    raise ValueError("A manager must be selected or defined in the job role.")
                employee = Employee(
                    first_name=request.form.get("first_name", "").strip(),
                    last_name=request.form.get("last_name", "").strip(),
                    username=request.form.get("username", "").strip(),
                    email=request.form.get("email", "").strip(),
                    job_role=role_name,
                    manager_dn=manager_dn,
                    attributes=attributes,
                )

                if not all([employee.first_name, employee.last_name, employee.username, employee.email]):
                    raise ValueError("All fields except password and attributes are required.")

                chosen_ou = request.form.get("user_ou") or roles[role_name].user_ou
                job_role = replace(roles[role_name], user_ou=chosen_ou or roles[role_name].user_ou)
                password = request.form.get("password", "") or None

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
        default_manager = selected_user.get("manager") if selected_user else None
        default_ou = _ou_from_dn(selected_user.get("distinguishedName")) if selected_user else None

        return render_template(
            "clone.html",
            query=query,
            search_results=search_results,
            selected_user=selected_user,
            default_attributes=attribute_defaults,
            default_manager=default_manager,
            default_ou=default_ou,
            managers=managers,
            ous=ous,
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
