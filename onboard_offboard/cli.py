"""Command line interface for the onboarding/offboarding toolkit."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

import typer

from .ad_client import ADClient
from .config import AppConfig, ConfigurationError, load_config
from .models import Employee, JobRole
from .storage import load_job_roles, save_job_roles
from .sync import run_sync_command

app = typer.Typer(help="Manage onboarding workflows across Active Directory and Microsoft 365.")
role_app = typer.Typer(help="Manage reusable job role templates.")
app.add_typer(role_app, name="role")


def _load_configuration(config_path: Optional[Path]) -> AppConfig:
    try:
        return load_config(config_path)
    except ConfigurationError as exc:
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)


def _load_roles(config: AppConfig) -> Dict[str, JobRole]:
    return load_job_roles(config.storage.job_roles_file)


@role_app.command("add")
def add_role(
    name: str = typer.Argument(..., help="Name of the job role."),
    description: Optional[str] = typer.Option(None, "--description", help="Friendly description."),
    user_ou: Optional[str] = typer.Option(None, "--user-ou", help="Target OU for this role."),
    default_manager_dn: Optional[str] = typer.Option(
        None, "--manager-dn", help="Distinguished name of the default manager."
    ),
    attribute: Optional[List[str]] = typer.Option(
        None,
        "--attribute",
        help="Additional attribute in key=value form. May be provided multiple times.",
    ),
    group: Optional[List[str]] = typer.Option(
        None,
        "--group",
        help="Distinguished name of an AD group to include with this role. May be provided multiple times.",
    ),
    config_path: Optional[Path] = typer.Option(
        None, "--config", help="Path to a specific settings file (overrides default)."
    ),
) -> None:
    """Add or update a job role template."""

    config = _load_configuration(config_path)
    roles = _load_roles(config)

    attributes: Dict[str, str] = {}
    if attribute:
        for item in attribute:
            if "=" not in item:
                raise typer.BadParameter("Attributes must be provided in key=value form.")
            key, value = item.split("=", 1)
            attributes[key] = value
    groups = list(dict.fromkeys(group or []))

    role = JobRole(
        name=name,
        description=description,
        user_ou=user_ou,
        default_manager_dn=default_manager_dn,
        attributes=attributes,
        groups=groups,
    )
    roles[name] = role
    save_job_roles(config.storage.job_roles_file, roles)
    typer.echo(f"Saved job role '{name}'.")


@role_app.command("list")
def list_roles(
    config_path: Optional[Path] = typer.Option(
        None, "--config", help="Path to a specific settings file (overrides default)."
    ),
) -> None:
    """Display configured job roles."""

    config = _load_configuration(config_path)
    roles = _load_roles(config)

    if not roles:
        typer.echo("No job roles configured yet.")
        raise typer.Exit(code=0)

    for role in roles.values():
        typer.echo(f"- {role.name}")
        if role.description:
            typer.echo(f"    description: {role.description}")
        if role.user_ou:
            typer.echo(f"    user_ou: {role.user_ou}")
        if role.default_manager_dn:
            typer.echo(f"    manager_dn: {role.default_manager_dn}")
        if role.attributes:
            for key, value in role.attributes.items():
                typer.echo(f"    {key}: {value}")
        if role.groups:
            typer.echo("    groups:")
            for group_dn in role.groups:
                typer.echo(f"      - {group_dn}")


@app.command("managers")
def show_managers(
    config_path: Optional[Path] = typer.Option(
        None, "--config", help="Path to a specific settings file (overrides default)."
    ),
    search_base: Optional[str] = typer.Option(None, help="Alternative search base for managers."),
    search_filter: Optional[str] = typer.Option(None, help="Override the LDAP search filter."),
) -> None:
    """List potential managers from Active Directory."""

    config = _load_configuration(config_path)

    with ADClient(config.ldap) as client:
        managers = client.list_potential_managers(search_base, search_filter)

    typer.echo(json.dumps(managers, indent=2))


@app.command("tree")
def show_tree(
    config_path: Optional[Path] = typer.Option(
        None, "--config", help="Path to a specific settings file (overrides default)."
    ),
    base_dn: Optional[str] = typer.Option(None, help="Start of the directory tree."),
    depth: int = typer.Option(2, help="Depth of organizational units to traverse."),
) -> None:
    """Display a portion of the directory tree for selecting OUs."""

    config = _load_configuration(config_path)

    with ADClient(config.ldap) as client:
        tree = client.fetch_directory_tree(base_dn, depth)

    typer.echo(json.dumps(tree, indent=2))


@app.command("onboard")
def onboard_user(
    first_name: str = typer.Argument(..., help="Employee first name."),
    last_name: str = typer.Argument(..., help="Employee last name."),
    username: str = typer.Argument(..., help="sAMAccountName/user principal prefix."),
    email: str = typer.Argument(..., help="Primary email address."),
    job_role: str = typer.Option(..., "--job-role", help="Job role template to apply."),
    manager_dn: Optional[str] = typer.Option(None, "--manager-dn", help="Manager distinguished name."),
    password: Optional[str] = typer.Option(
        None,
        "--password",
        help="Temporary password to assign during onboarding.",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
    ),
    extra_group: Optional[List[str]] = typer.Option(
        None,
        "--group",
        help="Additional group DN to assign to the user (repeatable).",
    ),
    config_path: Optional[Path] = typer.Option(
        None, "--config", help="Path to a specific settings file (overrides default)."
    ),
) -> None:
    """Provision a new employee in Active Directory and trigger sync."""

    config = _load_configuration(config_path)
    roles = _load_roles(config)

    if job_role not in roles:
        typer.echo(f"Unknown job role '{job_role}'. Use `role list` to see available roles.")
        raise typer.Exit(code=1)

    role = roles[job_role]
    effective_manager = manager_dn or role.default_manager_dn

    if not effective_manager:
        typer.echo("Manager DN must be supplied either on the command line or via the job role.")
        raise typer.Exit(code=1)

    groups = list(dict.fromkeys([*(role.groups or []), *(extra_group or [])]))

    employee = Employee(
        first_name=first_name,
        last_name=last_name,
        username=username,
        email=email,
        job_role=job_role,
        manager_dn=effective_manager,
        groups=groups,
    )

    with ADClient(config.ldap) as client:
        result = client.create_user(employee, role, password=password)

    typer.echo("User provisioned:")
    typer.echo(json.dumps(result, indent=2))

    typer.echo("Triggering directory sync...")
    try:
        run_sync_command(config.sync)
    except RuntimeError as exc:
        typer.echo(str(exc))


def run():
    app()


if __name__ == "__main__":
    run()
