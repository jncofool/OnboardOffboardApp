# OnboardOffboardApp

A browser-based onboarding and offboarding portal with a companion CLI purpose-built for hybrid Active Directory and Microsoft 365 environments. All behaviour is configuration-driven so you can point the toolkit at bundled mock data for demos or wire it up to your tenant for day-to-day operations.

## Features
- **Hybrid AD + Azure AD Support**: Manage both on-premises Active Directory groups and cloud-based Azure AD security groups, M365 Groups, and Distribution Lists
- **Configuration-driven**: YAML file and/or environment variables for flexible deployment
- **Responsive web UI**: Onboard, clone, and offboard users without command-line parameters
- **Job role templates**: Define default OUs, managers, groups, licenses, and attribute payloads
- **User cloning**: Duplicate existing users with all their group memberships (AD, Azure, M365, Distribution Lists)
- **License management**: Assign Microsoft 365 licenses with intelligent dependency handling (base licenses before add-ons)
- **Background worker**: Async license and group assignment with automatic retry logic
- **Distribution List support**: Exchange Online PowerShell integration for managing Distribution Lists
- **Mock mode**: Test the entire workflow without touching a live directory

## Prerequisites
- Python 3.10+
- Access to an Active Directory domain controller over LDAP/LDAPS, **or** use the bundled mock directory settings for local testing
- Service account credentials capable of creating user objects and running sync commands when targeting a real directory
- (Optional) Azure AD app registration with Microsoft Graph API permissions for M365 license and group management
- (Optional) Certificate-based authentication for Exchange Online PowerShell (Distribution List management)

Install the runtime dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start (Mock Mode)

The application ships with mock mode enabled by default, allowing you to test without any infrastructure:

```bash
# Install dependencies
pip install -r requirements.txt

# Launch the web portal (uses mock://demo by default)
python -m onboard_offboard.web
```

Navigate to `http://127.0.0.1:5000/` and start onboarding users. All operations are simulated and persisted to `data/mock_directory.yaml`.

## Configuration

### Basic Setup
1. Copy `config/settings.example.yaml` to `config/settings.yaml`
2. Edit the values to match your environment
3. Alternatively, use environment variables prefixed by `ONBOARD_` to override settings

### Mock Mode (Default)
Out of the box, the settings reference a mock directory (`server_uri: mock://demo`) so you can try the workflow without touching a live Active Directory instance.

```yaml
ldap:
  server_uri: mock://demo
  user_dn: CN=ServiceAccount,CN=Users,DC=example,DC=com
  password: ChangeMe123!
  base_dn: DC=example,DC=com
  user_ou: OU=Employees,DC=example,DC=com
sync:
  command: echo "Mock sync completed"
  shell: true
```

Mock runs persist to `data/mock_directory.yaml`, allowing you to inspect the resulting entries or reset the file between experiments.

### Production Setup

When ready to connect to production:

```yaml
ldap:
  server_uri: ldaps://dc01.example.com
  user_dn: CN=svc_onboarding,CN=Users,DC=example,DC=com
  password: ${ONBOARD_LDAP__PASSWORD}  # Use environment variable
  base_dn: DC=example,DC=com
  user_ou: OU=Employees,DC=example,DC=com
  use_ssl: true
  group_search_base: OU=Groups,DC=example,DC=com
sync:
  command: powershell.exe -Command "Start-ADSyncSyncCycle -PolicyType Delta"
  shell: false
  timeout: 180
```

### Microsoft 365 Integration

Configure Azure AD app registration for license and group management:

```yaml
m365:
  tenant_id: 00000000-0000-0000-0000-000000000000
  client_id: 00000000-0000-0000-0000-000000000000
  client_secret: ${ONBOARD_M365__CLIENT_SECRET}  # Use environment variable
  default_usage_location: US
  cert_thumbprint: 0000000000000000000000000000000000000000  # For Exchange Online
  exo_organization: example.com  # For Distribution Lists
```

**Required Microsoft Graph API Permissions (Application)**:
- `User.ReadWrite.All` - Create and manage users
- `Group.ReadWrite.All` - Manage group memberships
- `Organization.Read.All` - Read license SKUs

**Required Exchange Online Permissions**:
- Certificate-based authentication with `Exchange.ManageAsApp` role for Distribution List management

### Environment Variable Overrides

```bash
# Active Directory
export ONBOARD_LDAP__PASSWORD="SuperSecurePassword!"
export ONBOARD_LDAP__SERVER_URI="ldaps://dc01.example.com"

# Microsoft 365
export ONBOARD_M365__CLIENT_SECRET="your_client_secret_here"
export ONBOARD_M365__TENANT_ID="your_tenant_id"

# Sync Command
export ONBOARD_SYNC__COMMAND='powershell.exe -Command "Start-ADSyncSyncCycle -PolicyType Delta"'
```

### Configuration Reference

| Section | Key | Description |
| --- | --- | --- |
| `ldap` | `server_uri` | LDAP/LDAPS URI to a domain controller or `mock://demo` for offline testing |
|  | `user_dn` | Distinguished name for the service account |
|  | `password` | Password for the service account (use environment override) |
|  | `base_dn` | Root DN for lookups (e.g. `DC=example,DC=com`) |
|  | `user_ou` | Default OU where new users will be created |
|  | `use_ssl` | Whether to use LDAPS |
|  | `group_search_base` | Base DN for group searches (optional, restricts assignable groups) |
| `sync` | `command` | Command executed after provisioning to trigger synchronization |
|  | `shell` | Execute the sync command through the shell |
|  | `timeout` | Seconds to wait for the sync command to complete |
| `storage` | `job_roles_file` | Path to the YAML file containing job role definitions |
|  | `license_jobs_file` | Path to the JSON file for license job queue |
| `m365` | `tenant_id` | Azure AD tenant ID |
|  | `client_id` | Application (client) ID from app registration |
|  | `client_secret` | Client secret (use environment override) |
|  | `default_usage_location` | Two-letter country code (e.g. `US`) |
|  | `cert_thumbprint` | Certificate thumbprint for Exchange Online PowerShell |
|  | `exo_organization` | Primary domain for Exchange Online (e.g. `example.com`) |
| `auth` | `enabled` | Require Entra ID authentication for portal access |
|  | `tenant_id` | Azure AD tenant ID for authentication |
|  | `client_id` | Application ID for authentication |
|  | `allowed_groups` | List of security group object IDs (empty = allow all users) |

## Web Portal

Launch the portal:

```bash
python -m onboard_offboard.web
```

The server listens on `http://127.0.0.1:5000/` by default.

### Features

**Onboarding**
- Fill in user details (name, username, email, phone)
- Select job role (auto-applies default groups, licenses, manager, OU)
- Search and select manager from Active Directory
- Choose organizational unit
- Add/remove groups (AD and Azure AD)
- Select Microsoft 365 licenses with service plan toggles
- Set temporary password

**Cloning**
- Search for existing user
- Automatically copies all attributes, groups (AD + Azure + M365 + Distribution Lists), and licenses
- Adjust values before creating new account
- Perfect for onboarding similar roles

**Offboarding**
- Search for user
- Delete from Active Directory
- Triggers sync to remove from Azure AD/M365

**Configuration**
- Update AD connection settings
- Configure sync command
- Manage Microsoft 365 integration
- Create and edit job role templates
- Refresh license catalog

### Customization

```bash
export ONBOARD_WEB_HOST="0.0.0.0"   # Expose beyond localhost
export ONBOARD_WEB_PORT=8080        # Change the port
export ONBOARD_WEB_DEBUG=1          # Enable Flask debug mode
```

## Microsoft 365 License & Group Management

### How It Works

1. **User Creation**: User is created in Active Directory with AD groups
2. **Sync Trigger**: Configured sync command runs (e.g., Azure AD Connect)
3. **Background Worker**: After 90-second initial delay, worker looks up user in Azure AD
4. **License Assignment**: 
   - Sets `usageLocation` if missing
   - Assigns base licenses first (M365 E3/E5, Business Premium, etc.)
   - Waits 30 seconds for Exchange mailbox provisioning
   - Assigns add-on licenses (Teams Phone, etc.)
5. **Group Assignment**:
   - Azure AD security groups → Microsoft Graph API
   - M365 Groups (Unified) → Microsoft Graph API
   - Distribution Lists → Exchange Online PowerShell
   - Dynamic groups → Skipped (rule-based membership)
   - On-premises synced groups → Skipped (managed in AD)

### Supported Group Types

| Group Type | Assignment Method | Notes |
|------------|------------------|-------|
| AD Security Groups | LDAP during user creation | Traditional on-premises groups |
| Azure AD Security Groups | Microsoft Graph API | Cloud-only security groups |
| Microsoft 365 Groups | Microsoft Graph API | Unified groups with Teams/SharePoint |
| Distribution Lists | Exchange Online PowerShell | Email distribution (Graph API blocks these) |
| Dynamic Groups | Not assigned | Membership determined by rules |
| Synced Groups | Not assigned | Managed in on-premises AD |

### License Dependency Handling

The system intelligently orders license assignments:

**Base Licenses** (assigned first):
- Microsoft 365 E3, E5, F1, F3
- Microsoft 365 Business Basic, Standard, Premium
- Office 365 E1, E3, E5
- Visio Plan 2
- Project Plan 1, 3, 5

**Add-on Licenses** (assigned after base):
- Teams Phone
- Other add-ons requiring base license dependencies

### Retry Logic

- **Initial delay**: 90 seconds (wait for AD sync)
- **Retry schedule**: 30s, 30s, 60s, 120s, 300s
- **Max attempts**: 5 (stops after ~5.5 minutes)
- **400 errors**: Marked as complete immediately (except dependency errors)
- **User not found**: Retries until max attempts

### Distribution List Requirements

To manage Distribution Lists, configure certificate-based authentication:

1. Create self-signed certificate or use existing
2. Upload certificate to Azure AD app registration
3. Grant `Exchange.ManageAsApp` role
4. Configure in `settings.yaml`:
   ```yaml
   m365:
     client_id: your_app_id
     cert_thumbprint: your_cert_thumbprint
     exo_organization: example.com
   ```

## Command-Line Usage

All CLI commands use `python -m onboard_offboard`.

### Manage Job Roles

```bash
# Add or update a job role
python -m onboard_offboard role add "Software Engineer" \
  --description "Development team member" \
  --user-ou "OU=Engineering,OU=Employees,DC=example,DC=com" \
  --manager-dn "CN=Engineering Manager,OU=Managers,DC=example,DC=com" \
  --attribute department=Engineering \
  --attribute company="Example Corp"

# List configured roles
python -m onboard_offboard role list
```

### Discover Managers and OUs

```bash
python -m onboard_offboard managers
python -m onboard_offboard tree --depth 3
```

### Onboard a New Employee

```bash
python -m onboard_offboard onboard John Doe jdoe john.doe@example.com \
  --job-role "Software Engineer" \
  --password "TempPass123!"
```

## Portal Authentication (Entra ID)

Require users to sign in with Entra ID:

1. Create Azure AD app registration
2. Configure redirect URI: `http://localhost:5000/auth/callback`
3. Grant delegated permissions: `User.Read`, `GroupMember.Read.All`
4. Update `settings.yaml`:
   ```yaml
   auth:
     enabled: true
     tenant_id: your_tenant_id
     client_id: your_app_id
     client_secret: ${ONBOARD_AUTH__CLIENT_SECRET}
     allowed_groups:
       - security_group_object_id_1
       - security_group_object_id_2
   ```

Leave `allowed_groups` empty to allow any authenticated user in the tenant.

## Architecture

### Components

- **Web UI** (`onboard_offboard/web.py`): Flask application with responsive templates
- **AD Client** (`onboard_offboard/ad_client.py`): LDAP operations and mock directory
- **M365 Client** (`onboard_offboard/m365_client.py`): Microsoft Graph API integration
- **License Worker**: Background thread processing license/group assignments
- **Job Queue** (`onboard_offboard/license_jobs.py`): Persistent queue with retry logic

### Data Flow

```
User Input (Web/CLI)
  ↓
Create User in AD (with AD groups)
  ↓
Trigger Sync Command (Azure AD Connect)
  ↓
Queue License/Group Jobs (90s delay)
  ↓
Background Worker Processes Jobs
  ↓
  ├─ Assign Licenses (base → add-ons)
  ├─ Add to Azure Security Groups
  ├─ Add to M365 Groups
  └─ Add to Distribution Lists (Exchange PowerShell)
```

## Troubleshooting

### License Assignment Fails

**"User not found"**: User hasn't synced to Azure AD yet. Worker will retry automatically.

**"No available licenses"**: Tenant doesn't have available licenses for that SKU. Check license availability in M365 admin center.

**"Depends on service plan"**: Add-on license requires base license. System automatically orders licenses, but if base license failed, add-on will fail too.

### Distribution List Errors

**"Couldn't find object"**: User's Exchange mailbox hasn't provisioned yet. System waits 30 seconds after base license assignment, but may need longer.

**"Cannot update mail-enabled security group"**: This is a Distribution List and requires Exchange Online PowerShell. Ensure `cert_thumbprint` and `exo_organization` are configured.

### Group Assignment Issues

**Dynamic groups skipped**: Expected behavior. Dynamic groups use rule-based membership.

**On-premises synced groups skipped**: Expected behavior. These must be managed in Active Directory.

## Development

### Running Tests

```bash
pytest
```

### Code Structure

```
onboard_offboard/
├── web.py              # Flask web application
├── cli.py              # Command-line interface
├── ad_client.py        # Active Directory operations
├── m365_client.py      # Microsoft Graph API client
├── license_jobs.py     # Background job queue
├── models.py           # Data models
├── config.py           # Configuration management
├── storage.py          # Job role persistence
└── templates/          # HTML templates
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or pull request.

## Support

For issues, questions, or feature requests, please open a GitHub issue.
