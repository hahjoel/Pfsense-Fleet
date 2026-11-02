# pfSense Fleet Manager

Web dashboard to monitor and manage many pfSense firewalls at once, over **SSH**
or the **pfSense REST API package** (pfSense-pkg-RESTAPI v2). Each firewall picks its own method.
Same stack and look as the MikroTik Fleet Controller.

## Features
- Firewall inventory with groups (stored in `firewalls.json`, mode 600)
- Live status: online/offline, hostname, pfSense version, uptime, CPU, memory, total traffic, latency
  - **Traffic** = bytes in/out on the assigned interfaces (WAN, LAN, OPTx…) since boot, with the
    current rate computed between refreshes. Hover the cell for a per-interface breakdown.
- **Check updates**: runs `pfSense-upgrade -c` and shows a badge next to the version (⬆ new version / ✓ latest)
- **Reboot** the selected firewalls (with confirmation)
- **Users & SSH keys** across the selected firewalls:
  - one list of users merged across the selected firewalls, showing how many firewalls each user is on (e.g. `2/3`), plus groups, shell access and key count
  - create or update a user everywhere in one go: password, full name, groups, shell access, disabled
  - SSH keys: **add** (dedupes, keeps existing keys), **replace all**, or **remove** specific keys; the ✕ next to a key revokes it fleet-wide
  - when editing an existing user, only the fields you touch are changed, so a user's other settings stay as each firewall has them
  - guard rails: the built-in `admin` can't be disabled or deleted, and the account the manager logs in with can't be deleted
- **Logs**: system, firewall, DHCP, DNS resolver, gateways, auth, OpenVPN, IPsec, routing, NTP, nginx, PPP, captive portal. Choose a line count and an optional text filter
- **Backups**: **Save backup** pulls `/conf/config.xml` from each selected firewall and saves it on the server
  (`backups/<firewall-id>/config-<hostname>-<date>-<time>.xml`); download or delete from the Backups panel
- **Shell command** box for anything else (runs `/bin/sh` over SSH, or Diagnostics › Command Prompt over REST)

## Run
    pip install -r requirements.txt
    FLEET_PASSWORD=choose-a-password uvicorn app:app --host 0.0.0.0 --port 8080

Open http://SERVER:8080 and log in as `admin` / your FLEET_PASSWORD.

Docker:

    docker build -t pffleet .
    docker run -d -p 8080:8080 -e FLEET_PASSWORD=... -v pffleet:/data pffleet

## Firewall prep

### SSH method (no packages needed)
System › Advanced › Admin Access › **Enable Secure Shell** (password or "public key or password" auth).
Log in as `admin` (or `root`). Other users need root rights for upgrades, reboots and user changes,
and pfSense's shell for non-admin users isn't root.
User management over SSH needs **pfSense CE 2.7+ / Plus 23.05+**. It runs a small PHP helper
(`users.php`, sent over stdin and never stored on the firewall) that does what System › User Manager does.
Every change is saved with `write_config`, so it shows up in Diagnostics › Backup & Restore › Config History.

### REST method
Install **pfSense-pkg-RESTAPI v2** (https://github.com/pfrest/pfSense-pkg-RESTAPI) and, in
System › REST API › Settings, enable it and allow your manager server's IP. Then either:
- use **Basic auth** with a pfSense user (`admin`), or
- create an API key (System › REST API › Keys) and paste it in the **API key** field.

The API user needs privileges for the endpoints below. `admin` / `page-all` covers them all.

| Feature | REST endpoint |
|---|---|
| Status | `GET /api/v2/status/system`, `/system/version`, `/system/hostname`, `/status/interfaces` |
| Reboot | `POST /api/v2/diagnostics/reboot` |
| Users | `GET /api/v2/users`, `POST/PATCH/DELETE /api/v2/user`, `GET /api/v2/user/groups`, `PATCH /api/v2/user/group` |
| Update check, logs, backup, shell | `POST /api/v2/diagnostics/command_prompt` |

The package has no endpoint that only *checks* for updates (`/system/update` actually installs them),
so the update check runs `pfSense-upgrade -c` through `command_prompt`. If `command_prompt` is blocked for
the API user, logs fall back to the native `/status/logs/*` endpoints (system, firewall, DHCP, auth, OpenVPN),
but update checks and backups need it.

## Settings (env vars)
| Var | Default | |
|---|---|---|
| FLEET_PASSWORD | (required) | Web UI password |
| FLEET_USER | admin | Web UI username |
| FLEET_DB | ./firewalls.json | Inventory file |
| FLEET_BACKUPS | ./backups | Where downloaded backups are kept |
| FLEET_TIMEOUT | 8 | Per-firewall connect timeout (s) |
| FLEET_UPDATE_TIMEOUT | 180 | Max time for an update check (s) |
| FLEET_WORKERS | 32 | Max parallel connections |

## Security notes
- Firewall passwords and API keys are stored in plain text in `firewalls.json`; protect the host.
- The UI uses HTTP Basic auth. Put it behind HTTPS (nginx/Caddy reverse proxy) or a VPN, and never expose it raw to the internet.
- SSH host keys are auto-accepted on first connect; REST TLS certificates aren't verified unless you tick **Verify TLS certificate**.
- `config.xml` backups contain password hashes, keys and certificates. Treat the `backups/` folder as sensitive.
