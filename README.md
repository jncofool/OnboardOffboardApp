# OnboardOffboardApp

<<<<<<< ours
<<<<<<< ours
A command-line toolkit for orchestrating onboarding and offboarding workflows in a hybrid Active Directory and Microsoft 365 environment. The initial milestone focuses on configurable job roles, manager selection, and directory synchronization.

## Features

- Configuration driven (YAML file and/or environment variables) connection to Active Directory and sync tooling.
- Manage reusable job role templates that define default OUs, managers, and attribute payloads.
- Explore potential managers and the Active Directory OU tree directly from the command line.
- Provision new employees into AD and trigger a configurable directory sync command (for example Azure AD Connect).
=======
=======
>>>>>>> theirs
A browser-based onboarding and offboarding portal (with a companion CLI) for hybrid Active Directory and Microsoft 365 environments. The application keeps every setting configurable so you can point it at mock data for local demos or your production tenant for day-to-day operations.

## Features

- Configuration-driven (YAML file and/or environment variables) connection to Active Directory and sync tooling.
- Responsive web UI to onboard, clone, and offboard users without command-line parameters.
- Manage reusable job role templates that define default OUs, managers, and attribute payloads.
- Explore potential managers and the Active Directory OU tree via the portal or CLI.
- Provision new employees into AD, clone from existing accounts, and trigger a configurable directory sync command (for example Azure AD Connect).
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs

## Prerequisites

- Python 3.10+
- Access to an Active Directory domain controller over LDAP/LDAPS, **or** use the bundled mock
  directory settings for local testing.
- Service account credentials capable of creating user objects and running sync commands when
  targeting a real directory.

Install the runtime dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

1. Copy `config/settings.example.yaml` to `config/settings.yaml` and edit the values to match your environment.
2. Alternatively, point the CLI at a different file with `--config` or override individual values with environment variables prefixed by `ONBOARD_`.

Out of the box the settings reference a mock directory (`server_uri: mock://demo`) so you can try the
workflow without touching a live Active Directory instance. When you're ready to connect to production,
change `server_uri` to your LDAP/LDAPS endpoint and update the remaining values accordingly.

The default sync command simply echoes a message so the mock run succeeds everywhere. Replace it with
your automation (for example `Start-ADSyncSyncCycle`) when targeting production.

Mock runs persist to `data/mock_directory.yaml`, allowing you to inspect the resulting entries or reset
the file between experiments.

Example environment overrides:

```bash
export ONBOARD_LDAP__PASSWORD="SuperSecurePassword!"
export ONBOARD_SYNC__COMMAND="powershell.exe -Command \"Start-ADSyncSyncCycle -PolicyType Initial\""
```

### Configuration keys

| Section | Key | Description |
| --- | --- | --- |
| `ldap` | `server_uri` | LDAP/LDAPS URI to a domain controller or `mock://` URI for offline testing. |
|  | `user_dn` | Distinguished name for the service account used by the app. |
|  | `password` | Password for the service account (consider environment override). |
|  | `base_dn` | Root DN for lookups (e.g. `DC=example,DC=com`). |
|  | `user_ou` | Default OU where new users will be created. |
|  | `use_ssl` | Whether to use LDAPS. |
|  | `manager_search_filter` | LDAP filter used when listing potential managers. |
|  | `manager_attributes` | Additional attributes returned when listing managers. |
|  | `mock_data_file` | Path to YAML file with mock managers/tree data used in `mock://` mode. |
| `sync` | `command` | Command executed after provisioning to trigger synchronization. |
|  | `shell` | Execute the sync command through the shell (set to `true` for complex commands). |
|  | `timeout` | Seconds to wait for the sync command to complete. |
| `storage` | `job_roles_file` | Path to the YAML file containing job role definitions. |

<<<<<<< ours
<<<<<<< ours
## Usage

All commands are executed with `python -m onboard_offboard`.
=======
=======
>>>>>>> theirs
## Web portal

Launch the portal with:

```bash
python -m onboard_offboard.web
```

The server listens on `http://127.0.0.1:5000/` by default. Use the navigation bar to:

- Update the Active Directory connection, sync command, and storage locations from the **Configuration** page.
- Onboard new staff by filling in user details, selecting a job role, choosing an OU/manager from live directory data, and optionally supplying additional attributes.
- Clone an existing user—search the directory, pick a template account, adjust the prefilled values, and create the new profile.
- Offboard users by searching the directory, selecting the account, and deleting it. Each action triggers the configured sync command so Microsoft 365 stays in step.

Environment variables let you customise the listener:

```bash
export ONBOARD_WEB_HOST="0.0.0.0"   # expose beyond localhost
export ONBOARD_WEB_PORT=8080          # change the port
export ONBOARD_WEB_DEBUG=1            # enable Flask debug mode
```

> The web UI respects the same `config/settings.yaml` file as the CLI, so you can manage everything from the browser once the configuration is in place.

## Command-line usage

All CLI commands are executed with `python -m onboard_offboard`.
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs

### Manage job roles

```bash
# Add or update a job role
python -m onboard_offboard role add "Field Service Technician" \
  --description "Field service team member" \
  --user-ou "OU=Field Services,OU=Employees,DC=example,DC=com" \
  --manager-dn "CN=Alex Manager,OU=Managers,DC=example,DC=com" \
  --attribute department=FieldServices \
  --attribute company="Example Corp"

# List configured roles
python -m onboard_offboard role list
```

### Discover managers and OUs

```bash
python -m onboard_offboard managers
python -m onboard_offboard tree --depth 3
```

### Onboard a new employee

```bash
python -m onboard_offboard onboard Mark Daneshvar mdaneshvar mark.daneshvar@example.com \
  --job-role "Field Service Technician" \
  --password "P@ssw0rd!"
```

The onboarding command will create the user in Active Directory, assign the configured (or overridden) manager, and execute the sync command defined in your configuration so the user flows to Microsoft 365.

## Roadmap

- Attach security and Microsoft 365 groups during onboarding.
- Integrate with SaaS APIs for downstream provisioning.
- Automate offboarding workflows and asset recovery checklists.
