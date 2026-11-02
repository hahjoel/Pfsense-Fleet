"""
pfSense Fleet Manager
Web dashboard to monitor and manage many pfSense firewalls, each over SSH or
the pfSense REST API package (pfSense-pkg-RESTAPI v2).

Run:  FLEET_PASSWORD=changeme uvicorn app:app --host 0.0.0.0 --port 8080
"""
import asyncio
import base64
import json
import os
import re
import secrets
import shlex
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

import paramiko
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DB_FILE = Path(os.environ.get("FLEET_DB", BASE / "firewalls.json"))
UI_USER = os.environ.get("FLEET_USER", "admin")
UI_PASS = os.environ.get("FLEET_PASSWORD", "")
BACKUP_DIR = Path(os.environ.get("FLEET_BACKUPS", BASE / "backups"))
TIMEOUT = float(os.environ.get("FLEET_TIMEOUT", "8"))
UPDATE_TIMEOUT = float(os.environ.get("FLEET_UPDATE_TIMEOUT", "180"))
pool = ThreadPoolExecutor(max_workers=int(os.environ.get("FLEET_WORKERS", "32")))
sub_pool = ThreadPoolExecutor(max_workers=int(os.environ.get("FLEET_WORKERS", "32")))
USERS_PHP = (BASE / "users.php").read_text()
_lock = threading.Lock()

# in-memory caches (rebuilt after restart)
last_status: dict[str, dict] = {}     # fw id -> last good status
update_info: dict[str, dict] = {}     # fw id -> last update check
iface_cache: dict[str, tuple] = {}    # fw id -> (time, [(realif, descr)])

app = FastAPI(title="pfSense Fleet Manager")
security = HTTPBasic()
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


# --------------------------------------------------------------------- auth
def auth(creds: HTTPBasicCredentials = Depends(security)):
    if not UI_PASS:
        raise HTTPException(500, "Set FLEET_PASSWORD before starting the server.")
    ok = secrets.compare_digest(creds.username, UI_USER) and secrets.compare_digest(
        creds.password, UI_PASS
    )
    if not ok:
        raise HTTPException(401, "Bad credentials", headers={"WWW-Authenticate": "Basic"})
    return creds.username


# ------------------------------------------------------------------ storage
MASK = "********"


class Firewall(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str
    host: str
    method: Literal["ssh", "rest"] = "ssh"
    port: Optional[int] = None          # default: 22 for SSH, 443 for REST
    username: str = "admin"
    password: str = ""
    api_key: str = ""                   # REST only; used instead of user/password if set
    verify_ssl: bool = False            # REST only; pfSense ships a self-signed cert
    group: str = ""


def load() -> dict[str, Firewall]:
    if not DB_FILE.exists():
        return {}
    data = json.loads(DB_FILE.read_text() or "[]")
    return {f["id"]: Firewall(**f) for f in data}


def save(fws: dict[str, Firewall]):
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = DB_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps([f.model_dump() for f in fws.values()], indent=2))
    os.chmod(tmp, 0o600)  # file holds firewall credentials
    tmp.replace(DB_FILE)


def public(f: Firewall) -> dict:
    d = f.model_dump()
    d["password"] = MASK if f.password else ""
    d["api_key"] = MASK if f.api_key else ""
    return d


def port_of(f: Firewall) -> int:
    return f.port or (22 if f.method == "ssh" else 443)


# ---------------------------------------------------------------- transport
def ssh_run(f: Firewall, cmd: str, timeout: float = None, stdin: str = None) -> str:
    """Run a shell command. pfSense's admin/root shell (rc.initial) hands
    non-interactive commands to /bin/sh -c, so this works for admin too."""
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(f.host, port=port_of(f), username=f.username, password=f.password,
              timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT,
              look_for_keys=False, allow_agent=False)
    try:
        i, out, err = c.exec_command(cmd, timeout=timeout or TIMEOUT * 4)
        if stdin is not None:
            i.write(stdin)
            i.channel.shutdown_write()
        text = out.read().decode(errors="replace")
        e = err.read().decode(errors="replace")
    finally:
        c.close()
    return text + (("\n" + e) if e.strip() else "")


def rest(f: Firewall, method: str, path: str, body=None, query=None, timeout=None):
    host = f"[{f.host}]" if ":" in f.host and not f.host.startswith("[") else f.host
    url = f"https://{host}:{port_of(f)}{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if f.api_key:
        headers["X-API-Key"] = f.api_key
    else:
        tok = base64.b64encode(f"{f.username}:{f.password}".encode()).decode()
        headers["Authorization"] = f"Basic {tok}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl.create_default_context()
    if not f.verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout or TIMEOUT * 4, context=ctx) as r:
            payload = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("message") or e.reason
        except Exception:
            msg = e.reason
        raise RuntimeError(f"REST API {e.code} on {path}: {msg}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"REST API unreachable: {e.reason}") from None
    return payload.get("data")


def shell(f: Firewall, cmd: str, timeout: float = None) -> str:
    """Run a shell command on either transport. REST uses the package's
    /diagnostics/command_prompt endpoint (same thing as Diagnostics > Command Prompt)."""
    if f.method == "ssh":
        return ssh_run(f, cmd, timeout)
    d = rest(f, "POST", "/api/v2/diagnostics/command_prompt", {"command": cmd},
             timeout=timeout) or {}
    return d.get("output") or ""


def parallel(*fns):
    """Run independent callables concurrently (used for REST status calls)."""
    futs = [sub_pool.submit(fn) for fn in fns]
    return [fu.result() for fu in futs]


# ------------------------------------------------------------------- status
def fmt_uptime(sec: int) -> str:
    d, rem = divmod(int(sec), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{d}d {h}h {m}m" if d else f"{h}h {m}m"


def uptime_from_text(s: str) -> Optional[str]:
    """REST returns e.g. '12 Days 03 Hours 41 Minutes 09 Seconds'."""
    if not s:
        return None
    sec = 0
    for n, unit in re.findall(r"(\d+)\s*(day|hour|minute|second)", s, re.I):
        sec += int(n) * {"day": 86400, "hour": 3600, "minute": 60, "second": 1}[unit.lower()]
    return fmt_uptime(sec) if sec else s


SEP = "@@FLEET@@"
IFACE_PHP = ("/usr/local/bin/php -r 'require_once(\"config.inc\");require_once(\"interfaces.inc\");"
             "foreach(get_configured_interface_with_descr() as $i=>$d){"
             "echo get_real_interface($i),\"\\t\",$d,\"\\n\";}' 2>/dev/null")


def ssh_status_cmd(with_ifaces: bool) -> str:
    parts = [
        "cat /etc/version 2>/dev/null",
        "hostname",
        "sysctl -n kern.boottime",
        "date +%s",
        "sysctl -n kern.cp_time",
        "sleep 1; sysctl -n kern.cp_time",
        "for o in vm.stats.vm.v_page_count vm.stats.vm.v_inactive_count "
        "vm.stats.vm.v_laundry_count vm.stats.vm.v_free_count; "
        "do sysctl -n $o 2>/dev/null || echo 0; done",
        "netstat -ibn --libxo json 2>/dev/null",
        IFACE_PHP if with_ifaces else "true",
    ]
    return f"; echo {SEP}; ".join(parts)


def netstat_bytes(js: str) -> dict[str, tuple[int, int]]:
    """{ifname: (rx_bytes, tx_bytes)} from link-level rows of netstat -ibn."""
    out = {}
    try:
        rows = json.loads(js)["statistics"]["interface"]
    except Exception:
        return out
    for r in rows:
        if not str(r.get("network", "")).startswith("<Link"):
            continue
        out[r.get("name")] = (int(r.get("received-bytes", 0) or 0),
                              int(r.get("sent-bytes", 0) or 0))
    return out


def ssh_status(f: Firewall) -> dict:
    cached = iface_cache.get(f.id)
    fresh = cached and time.time() - cached[0] < 600
    sections = [s.strip() for s in ssh_run(f, ssh_status_cmd(not fresh)).split(SEP)]
    if len(sections) < 9:
        raise RuntimeError("Unexpected output — is this a pfSense shell?\n" + sections[0][:300])
    ver, host, boot, now, cp1, cp2, mem, nets, ifs = sections[:9]

    m = re.search(r"sec = (\d+)", boot)
    up = fmt_uptime(int(now) - int(m.group(1))) if m and now.isdigit() else None

    cpu = None
    try:
        a = [int(x) for x in cp1.split()]
        b = [int(x) for x in cp2.split()]
        dt = sum(b) - sum(a)
        cpu = round(100 * (1 - (b[4] - a[4]) / dt)) if dt > 0 else 0
    except Exception:
        pass

    memp = None
    try:
        total, inact, laundry, free = [int(x) for x in mem.split()[:4]]
        memp = round(100 * (total - inact - laundry - free) / total)
    except Exception:
        pass

    if fresh:
        assigned = cached[1]
    else:
        assigned = [tuple(l.split("\t", 1)) for l in ifs.splitlines() if "\t" in l]
        if assigned:
            iface_cache[f.id] = (time.time(), assigned)
    counters = netstat_bytes(nets)
    ifaces = []
    if assigned:
        for real, descr in assigned:
            if real in counters:
                ifaces.append({"name": descr, "if": real,
                               "rx": counters[real][0], "tx": counters[real][1]})
    else:  # PHP unavailable: fall back to physical NICs
        skip = re.compile(r"^(lo|enc|pflog|pfsync|ovpn|tun|gif|gre|ipsec|wg|bridge|lagg|vlan)\d*|\.")
        for n, (rx, tx) in counters.items():
            if not skip.search(n or ""):
                ifaces.append({"name": n, "if": n, "rx": rx, "tx": tx})

    return {
        "hostname": host,
        "version": ver.splitlines()[0] if ver else None,
        "uptime": up,
        "cpu": cpu,
        "mem": memp,
        "rx": sum(i["rx"] for i in ifaces),
        "tx": sum(i["tx"] for i in ifaces),
        "ifaces": ifaces,
    }


def rest_status(f: Firewall) -> dict:
    sysst, ver, hn, ifs = parallel(
        lambda: rest(f, "GET", "/api/v2/status/system") or {},
        lambda: rest(f, "GET", "/api/v2/system/version") or {},
        lambda: rest(f, "GET", "/api/v2/system/hostname") or {},
        lambda: rest(f, "GET", "/api/v2/status/interfaces") or [],
    )
    ifaces = [{"name": i.get("descr") or i.get("name"), "if": i.get("hwif"),
               "rx": int(i.get("inbytes") or 0), "tx": int(i.get("outbytes") or 0)}
              for i in ifs]
    host = hn.get("hostname") or ""
    if hn.get("domain"):
        host = f"{host}.{hn['domain']}"
    cpu, mem = sysst.get("cpu_usage"), sysst.get("mem_usage")
    return {
        "hostname": host,
        "version": ver.get("version"),
        "uptime": uptime_from_text(sysst.get("uptime")),
        "cpu": round(cpu) if isinstance(cpu, (int, float)) and cpu >= 0 else None,
        "mem": round(mem) if isinstance(mem, (int, float)) and mem >= 0 else None,
        "rx": sum(i["rx"] for i in ifaces),
        "tx": sum(i["tx"] for i in ifaces),
        "ifaces": ifaces,
    }


def get_status(f: Firewall) -> dict:
    t0 = time.time()
    s = ssh_status(f) if f.method == "ssh" else rest_status(f)
    s.update(online=True, latency_ms=round((time.time() - t0) * 1000), ts=time.time())
    last_status[f.id] = s
    return s


# ------------------------------------------------------------------ updates
def check_updates(f: Firewall) -> dict:
    out = shell(f, "/usr/local/sbin/pfSense-upgrade -c 2>&1; echo \"exit=$?\"",
                timeout=UPDATE_TIMEOUT).strip()
    low = out.lower()
    info = {"checked": time.time(), "state": "unknown", "available": None}
    m = re.search(r"([0-9][0-9A-Za-z._-]*)\s+version of pfsense is available", out, re.I) \
        or re.search(r"new version[^0-9]*([0-9][0-9A-Za-z._-]*)", out, re.I)
    # check "available" first: repo refresh lines also say "repository is up to date"
    if m or re.search(r"version of pfsense is available|upgrade is available", low):
        info["state"] = "available"
        info["available"] = m.group(1) if m else None
    elif "system is up to date" in low or "up to date" in low:
        info["state"] = "current"
    elif "error" in low or "unable" in low or "not found" in low:
        info["state"] = "error"
    update_info[f.id] = info
    summary = {"current": "✓ Up to date",
               "available": f"⬆ Update available{': ' + info['available'] if info['available'] else ''}",
               "error": "⚠ Check failed", "unknown": "? Could not interpret result"}[info["state"]]
    return {"text": f"{summary}\n\n{out}"}


# ------------------------------------------------------------------- reboot
def reboot(f: Firewall) -> str:
    try:
        if f.method == "ssh":
            # daemon(8) detaches so the SSH session can close before rc.reboot runs
            ssh_run(f, "/usr/sbin/daemon -f /bin/sh -c 'sleep 2; /etc/rc.reboot' "
                       ">/dev/null 2>&1; echo queued")
        else:
            rest(f, "POST", "/api/v2/diagnostics/reboot", {})
    except Exception as e:
        if f.method == "rest" and "unreachable" in str(e):
            return "Reboot sent (connection dropped as expected)"
        raise
    update_info.pop(f.id, None)
    return "Reboot sent — the firewall will be back in a few minutes."


# --------------------------------------------------------------------- logs
LOGS = {
    "system": "General / system", "filter": "Firewall", "dhcpd": "DHCP",
    "resolver": "DNS resolver", "gateways": "Gateways", "auth": "Authentication",
    "openvpn": "OpenVPN", "ipsec": "IPsec", "routing": "Routing", "ntpd": "NTP",
    "nginx": "Web GUI (nginx)", "ppp": "PPP", "portalauth": "Captive portal",
}
REST_LOGS = {"system": "system", "filter": "firewall", "dhcpd": "dhcp",
             "auth": "auth", "openvpn": "openvpn"}


def read_log(f: Firewall, log: str, lines: int, flt: str) -> str:
    path = f"/var/log/{log}.log"
    src = f"grep -i -F -e {shlex.quote(flt)} {path}" if flt else f"cat {path}"
    cmd = (f"if [ -f {path} ]; then {src} | tail -n {lines}; "
           f"else echo 'No {path} on this firewall'; fi")
    try:
        text = shell(f, cmd).rstrip()
    except RuntimeError:
        # command_prompt may be blocked for this API user; try the native log endpoint
        if f.method != "rest" or log not in REST_LOGS:
            raise
        rows = rest(f, "GET", f"/api/v2/status/logs/{REST_LOGS[log]}",
                    query={"limit": max(lines * 4 if flt else lines, lines)}) or []
        out = [r.get("text", "") for r in rows]
        if flt:
            out = [l for l in out if flt.lower() in l.lower()]
        text = "\n".join(out[-lines:])
    return text or "(log is empty)"


# ------------------------------------------------------------------ backups
def backup_and_fetch(f: Firewall) -> dict:
    out = shell(f, f"hostname; echo {SEP}; cat /conf/config.xml", timeout=TIMEOUT * 8)
    if SEP not in out:
        raise RuntimeError(out.strip()[:300] or "No output")
    host, xml = out.split(SEP, 1)
    xml = xml.lstrip("\r\n")
    if "<pfsense>" not in xml or "</pfsense>" not in xml:
        raise RuntimeError("Did not receive a complete config.xml:\n" + xml[:300])
    label = host.strip() or f.host
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-.") or "pfsense"
    name = f"config-{slug}-{datetime.now():%Y%m%d-%H%M%S}.xml"
    d = BACKUP_DIR / f.id
    d.mkdir(parents=True, exist_ok=True)
    dest = d / name
    dest.write_text(xml)
    os.chmod(dest, 0o600)
    return {"text": f"Saved {name} ({max(1, dest.stat().st_size // 1024)} KB)",
            "download": f"/api/backups/{f.id}/{name}"}


def backup_path(fid: str, fname: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9]+", fid) or not re.fullmatch(r"[A-Za-z0-9_.-]+\.xml", fname):
        raise HTTPException(400, "Bad backup name")
    p = BACKUP_DIR / fid / fname
    if not p.is_file():
        raise HTTPException(404, "Backup not found")
    return p


# -------------------------------------------------------- users & SSH keys
def key_id(line: str) -> Optional[str]:
    """Identity of an authorized_keys line = its key blob (ignores options/comments)."""
    for tok in line.split():
        if len(tok) > 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", tok):
            return tok
    return None


def split_keys(text: str) -> list[str]:
    return [l.strip() for l in (text or "").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def merge_keys(existing: str, given: str, mode: str) -> str:
    cur, new = split_keys(existing), split_keys(given)
    if mode == "replace":
        return "\n".join(new)
    if mode == "remove":
        drop = {key_id(k) or k for k in new}
        return "\n".join(k for k in cur if (key_id(k) or k) not in drop)
    seen = {key_id(k) or k for k in cur}
    for k in new:
        kid = key_id(k) or k
        if kid not in seen:
            cur.append(k)
            seen.add(kid)
    return "\n".join(cur)


def ssh_users_php(f: Firewall, payload: dict) -> dict:
    blob = base64.b64encode(json.dumps(payload).encode()).decode()
    out = ssh_run(f, "/usr/local/bin/php -q", timeout=TIMEOUT * 6,
                  stdin=USERS_PHP.replace("__PAYLOAD__", blob))
    m = re.search(r"@@FLEET-JSON@@(.*)@@FLEET-END@@", out, re.S)
    if not m:
        raise RuntimeError("Unexpected output from pfSense PHP:\n" + out.strip()[:500])
    res = json.loads(m.group(1))
    if "error" in res:
        raise RuntimeError(res["error"])
    return res


def users_list(f: Firewall) -> dict:
    if f.method == "ssh":
        return ssh_users_php(f, {"op": "list"})
    users, groups = parallel(lambda: rest(f, "GET", "/api/v2/users") or [],
                             lambda: rest(f, "GET", "/api/v2/user/groups") or [])
    out = []
    for u in users:
        out.append({
            "id": u.get("id"), "name": u.get("name"), "uid": u.get("uid"),
            "descr": u.get("descr") or "", "scope": u.get("scope") or "",
            "disabled": bool(u.get("disabled")), "priv": u.get("priv") or [],
            "groups": sorted(g["name"] for g in groups
                             if g.get("name") != "all" and u.get("name") in (g.get("member") or [])),
            "keys": u.get("authorizedkeys") or "",
        })
    return {"users": out, "groups": [g["name"] for g in groups if g.get("name") != "all"],
            "_groups_raw": groups}


class UserSpec(BaseModel):
    name: str
    password: Optional[str] = None       # None/"" = keep (required for new users)
    descr: Optional[str] = None          # None = leave unchanged
    disabled: Optional[bool] = None
    shell: Optional[bool] = None         # "User - System: Shell account access"
    groups: Optional[list[str]] = None   # full membership list, None = unchanged
    keys: Optional[str] = None           # authorized keys text, None = unchanged
    key_mode: Literal["append", "replace", "remove"] = "append"


def user_set(f: Firewall, s: UserSpec) -> str:
    cur = users_list(f)
    existing = next((u for u in cur["users"] if u["name"] == s.name), None)
    if s.disabled and existing and (existing.get("uid") == 0 or existing.get("scope") == "system"):
        raise RuntimeError("The built-in admin account cannot be disabled.")
    if s.disabled and s.name == f.username:
        raise RuntimeError("Refusing to disable the account this manager logs in with.")
    keys = None
    if s.keys is not None and (s.keys.strip() or s.key_mode == "replace"):
        keys = merge_keys(existing["keys"] if existing else "", s.keys, s.key_mode)

    if f.method == "ssh":
        payload = {"op": "set", "name": s.name, "password": s.password or None,
                   "descr": s.descr, "disabled": s.disabled, "shell": s.shell,
                   "groups": s.groups, "keys": keys}
        text = ssh_users_php(f, payload)["text"]
    else:
        if s.groups is not None:  # validate before changing anything
            missing = set(s.groups) - {g["name"] for g in cur["_groups_raw"]}
            if missing:
                raise RuntimeError(f"Unknown group(s): {', '.join(sorted(missing))}")
        body = {}
        if s.descr is not None:
            body["descr"] = s.descr
        if s.disabled is not None:
            body["disabled"] = s.disabled
        if s.password:
            body["password"] = s.password
        if keys is not None:
            body["authorizedkeys"] = keys
        if s.shell is not None:
            priv = [p for p in (existing["priv"] if existing else []) if p != "user-shell-access"]
            body["priv"] = priv + (["user-shell-access"] if s.shell else [])
        if existing:
            if body:
                rest(f, "PATCH", "/api/v2/user", {"id": existing["id"], **body})
            text = f"Updated user {s.name}"
        else:
            if not s.password:
                raise RuntimeError(f"User '{s.name}' does not exist here; "
                                   "a password is required to create it.")
            rest(f, "POST", "/api/v2/user", {"name": s.name, **body})
            text = f"Created user {s.name}"
        if s.groups is not None:
            for g in cur["_groups_raw"]:
                if g.get("name") == "all":
                    continue
                members = list(g.get("member") or [])
                want, have = g["name"] in s.groups, s.name in members
                if want != have:
                    members = members + [s.name] if want else [m for m in members if m != s.name]
                    rest(f, "PATCH", "/api/v2/user/group", {"id": g["id"], "member": members})
    parts = []
    if keys is not None:
        n = len(split_keys(keys))
        parts.append(f"{n} SSH key{'s' if n != 1 else ''} now authorized")
    if s.password:
        parts.append("password set")
    return text + (" — " + ", ".join(parts) if parts else "")


def user_delete(f: Firewall, name: str) -> str:
    if name == f.username:
        raise RuntimeError("Refusing to delete the account this manager logs in with.")
    if f.method == "ssh":
        return ssh_users_php(f, {"op": "delete", "name": name})["text"]
    cur = users_list(f)
    u = next((u for u in cur["users"] if u["name"] == name), None)
    if not u:
        return f"User {name} not present (nothing to do)"
    if u.get("uid") == 0 or u.get("scope") == "system":
        raise RuntimeError(f"{name} is a built-in account and cannot be deleted.")
    rest(f, "DELETE", "/api/v2/user", query={"id": u["id"]})
    return f"Deleted user {name}"


# ------------------------------------------------------------------ helpers
async def in_thread(fn, *a):
    return await asyncio.get_running_loop().run_in_executor(pool, fn, *a)


async def safe(fn, *a) -> dict:
    try:
        return {"ok": True, "result": await in_thread(fn, *a)}
    except Exception as e:  # report per-firewall failures, don't abort the batch
        msg = str(e) if isinstance(e, RuntimeError) else f"{type(e).__name__}: {e}"
        return {"ok": False, "error": msg}


def targets(ids: list[str]) -> list[Firewall]:
    fws = load()
    t = [fws[i] for i in ids if i in fws]
    if not t:
        raise HTTPException(400, "No valid firewalls selected")
    return t


async def fan_out(ids, fn, *a) -> dict:
    t = targets(ids)
    res = await asyncio.gather(*(safe(fn, f, *a) for f in t))
    return {f.id: r for f, r in zip(t, res)}


# --------------------------------------------------------------------- API
@app.get("/")
def index(_=Depends(auth)):
    return FileResponse(BASE / "static" / "index.html")


@app.get("/api/firewalls")
def list_firewalls(_=Depends(auth)):
    return [public(f) for f in load().values()]


@app.post("/api/firewalls")
def add_firewall(f: Firewall, _=Depends(auth)):
    with _lock:
        fws = load()
        f.id = uuid.uuid4().hex[:8]
        fws[f.id] = f
        save(fws)
    return public(f)


@app.put("/api/firewalls/{fid}")
def update_firewall(fid: str, f: Firewall, _=Depends(auth)):
    with _lock:
        fws = load()
        if fid not in fws:
            raise HTTPException(404)
        if f.password in ("", MASK):
            f.password = fws[fid].password  # keep existing secret
        if f.api_key == MASK:
            f.api_key = fws[fid].api_key
        f.id = fid
        fws[fid] = f
        save(fws)
    iface_cache.pop(fid, None)
    return public(f)


@app.delete("/api/firewalls/{fid}")
def delete_firewall(fid: str, _=Depends(auth)):
    with _lock:
        fws = load()
        fws.pop(fid, None)
        save(fws)
    for c in (last_status, update_info, iface_cache):
        c.pop(fid, None)
    return {"ok": True}


@app.get("/api/status")
async def status_all(_=Depends(auth)):
    fws = list(load().values())
    results = await asyncio.gather(*(safe(get_status, f) for f in fws))
    out = {}
    for f, res in zip(fws, results):
        s = res["result"] if res["ok"] else {"online": False, "error": res["error"]}
        s["update"] = update_info.get(f.id)
        out[f.id] = s
    return out


class Ids(BaseModel):
    ids: list[str]


class Exec(Ids):
    command: str


@app.post("/api/exec")
async def exec_cmd(body: Exec, _=Depends(auth)):
    return await fan_out(body.ids, lambda f: shell(f, body.command).strip() or "(ok, no output)")


class Action(Ids):
    action: Literal["check-updates", "reboot", "backup"]


@app.post("/api/action")
async def action(body: Action, _=Depends(auth)):
    fn = {"check-updates": check_updates, "reboot": reboot, "backup": backup_and_fetch}[body.action]
    return await fan_out(body.ids, fn)


@app.get("/api/logs")
def log_names(_=Depends(auth)):
    return LOGS


class LogReq(Ids):
    log: str
    lines: int = Field(200, ge=1, le=5000)
    filter: str = ""


@app.post("/api/logs")
async def logs(body: LogReq, _=Depends(auth)):
    if body.log not in LOGS:
        raise HTTPException(400, "Unknown log")
    return await fan_out(body.ids, read_log, body.log, body.lines, body.filter)


@app.post("/api/users/list")
async def api_users_list(body: Ids, _=Depends(auth)):
    def strip(f):
        r = users_list(f)
        r.pop("_groups_raw", None)
        return r
    return await fan_out(body.ids, strip)


class UserSet(Ids):
    user: UserSpec


@app.post("/api/users/set")
async def api_user_set(body: UserSet, _=Depends(auth)):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", body.user.name) or body.user.name[0] == "-":
        raise HTTPException(400, "Invalid username")
    return await fan_out(body.ids, user_set, body.user)


class UserDel(Ids):
    name: str


@app.post("/api/users/delete")
async def api_user_delete(body: UserDel, _=Depends(auth)):
    return await fan_out(body.ids, user_delete, body.name)


@app.get("/api/backups")
def list_backups(_=Depends(auth)):
    fws = load()
    out = []
    if BACKUP_DIR.exists():
        for d in BACKUP_DIR.iterdir():
            if not d.is_dir():
                continue
            for p in d.glob("*.xml"):
                st = p.stat()
                out.append({
                    "fw_id": d.name,
                    "firewall": fws[d.name].name if d.name in fws else f"(deleted {d.name})",
                    "file": p.name, "size": st.st_size, "mtime": st.st_mtime,
                    "url": f"/api/backups/{d.name}/{p.name}",
                })
    return sorted(out, key=lambda x: -x["mtime"])


@app.get("/api/backups/{fid}/{fname}")
def download_backup(fid: str, fname: str, _=Depends(auth)):
    return FileResponse(backup_path(fid, fname), filename=fname, media_type="application/xml")


@app.delete("/api/backups/{fid}/{fname}")
def delete_backup(fid: str, fname: str, _=Depends(auth)):
    backup_path(fid, fname).unlink()
    return {"ok": True}
