const $ = s => document.querySelector(s);
let fws = [], status = {}, rates = {}, selected = new Set(), editing = null, timer = null;

async function api(path, opts={}) {
  const r = await fetch(path, {headers:{"Content-Type":"application/json"}, ...opts});
  if (!r.ok) {
    const j = await r.json().catch(()=>({}));
    const d = j.detail;
    throw new Error(Array.isArray(d) ? d.map(x=>x.msg).join("; ") : (d || r.statusText));
  }
  return r.json();
}
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const post = (path, body) => api(path, {method:"POST", body:JSON.stringify(body)});

function bar(v){ if(v==null||v==="") return "—"; v=+v;
  return `<span class="bar"><i class="${v>80?'hi':''}" style="width:${Math.min(v,100)}%"></i></span>${v}%`; }

function bytes(n){ if(n==null) return "—"; const u=["B","KB","MB","GB","TB","PB"]; let i=0;
  while(n>=1024 && i<u.length-1){ n/=1024; i++; } return (i?n.toFixed(n<10?2:1):n)+" "+u[i]; }
function bps(n){ const u=["b/s","Kb/s","Mb/s","Gb/s"]; let i=0; n*=8;
  while(n>=1000 && i<u.length-1){ n/=1000; i++; } return (i?n.toFixed(n<10?1:0):Math.round(n))+" "+u[i]; }

function traffic(id, s){
  const r = rates[id];
  const tip = (s.ifaces||[]).map(i=>`${i.name} (${i.if}): ↓ ${bytes(i.rx)}  ↑ ${bytes(i.tx)}`).join("\n");
  return `<td class="tr" title="${esc(tip)}">↓ ${bytes(s.rx)}${r?` <span class="rate">${bps(r.rx)}</span>`:""}
    <br>↑ ${bytes(s.tx)}${r?` <span class="rate">${bps(r.tx)}</span>`:""}</td>`;
}

function updBadge(u){
  if(!u) return "";
  const when = new Date(u.checked*1000).toLocaleString();
  const t = {current:["✓ latest","current"], available:[`⬆ ${u.available||"update"}`,"available"],
             error:["check failed","error"], unknown:["?","error"]}[u.state] || ["?",""];
  return `<span class="upd ${t[1]}" title="Checked ${esc(when)}">${esc(t[0])}</span>`;
}

function render(){
  const g = $("#groupFilter").value;
  const groups = [...new Set(fws.map(f=>f.group).filter(Boolean))].sort();
  $("#groupFilter").innerHTML = `<option value="">All groups</option>` +
    groups.map(x=>`<option ${x===g?"selected":""}>${esc(x)}</option>`).join("");
  const list = fws.filter(f=>!g || f.group===g);
  $("#empty").hidden = fws.length > 0;
  $("#rows").innerHTML = list.map(f=>{
    const s = status[f.id];
    const dot = !s ? "" : s.online ? "on" : "off";
    const rest = !s ? `<td colspan="7" class="hint">checking…</td>` :
      s.online ? `<td>${esc(s.hostname)}</td><td>${esc(s.version)}${updBadge(s.update)}</td>
        <td>${esc(s.uptime)}</td><td>${bar(s.cpu)}</td><td>${bar(s.mem)}</td>${traffic(f.id,s)}
        <td class="num">${s.latency_ms}</td>`
      : `<td colspan="7"><span class="err" title="${esc(s.error)}">${esc(s.error)}</span></td>`;
    return `<tr>
      <td><input type="checkbox" data-sel="${f.id}" ${selected.has(f.id)?"checked":""}></td>
      <td><span class="dot ${dot}"></span></td>
      <td>${esc(f.name)} ${f.group?`<span class="tag">${esc(f.group)}</span>`:""}</td>
      <td style="font-family:var(--mono)">${esc(f.host)}</td>
      <td><span class="tag">${f.method==="ssh"?"SSH":"REST"}</span></td>
      ${rest}
      <td><button class="link" data-edit="${f.id}">edit</button></td></tr>`;
  }).join("");
  const on = Object.values(status).filter(s=>s.online).length;
  const upd = Object.values(status).filter(s=>s.update?.state==="available").length;
  $("#sum").textContent = `${fws.length} firewalls · ${on} online · ${fws.length-on} down` +
    (upd ? ` · ${upd} update${upd>1?"s":""} available` : "");
  $("#selCount").textContent = selected.size;
  $("#selAll").checked = list.length && list.every(f=>selected.has(f.id));
}

async function loadFws(){ fws = await api("/api/firewalls"); render(); }
async function loadStatus(){
  $("#refresh").disabled = true;
  try {
    const prev = status, next = await api("/api/status");
    for (const [id,s] of Object.entries(next)) {
      const p = prev[id];
      if (s.online && p?.online && s.ts>p.ts && s.rx>=p.rx && s.tx>=p.tx) {
        const dt = s.ts - p.ts;
        rates[id] = {rx:(s.rx-p.rx)/dt, tx:(s.tx-p.tx)/dt};
      } else if (!s.online) delete rates[id];
    }
    status = next;
  } catch(e){ alert(e.message); }
  $("#refresh").disabled = false; render();
}

// ------------------------------------------------------------ output popup
let lastResults = null;

function openOut(label, n){
  $("#outTitle").textContent = label;
  $("#outMeta").textContent = "";
  $("#out").innerHTML = `<div class="hint" style="padding:16px 0"><span class="spin"></span>Running on ${n ?? selected.size} firewall(s)…</div>`;
  if (!$("#outDlg").open) $("#outDlg").showModal();
}

function show(results, label){
  lastResults = {results, label, time: new Date().toLocaleTimeString()};
  $("#lastOut").disabled = false;
  render_out();
  if (!$("#outDlg").open) $("#outDlg").showModal();
}

const resText = res => res.ok ? (res.result?.text ?? res.result) : res.error;

function render_out(){
  const {results, label, time} = lastResults;
  const entries = Object.entries(results);
  const ok = entries.filter(([,r])=>r.ok).length;
  $("#outTitle").textContent = label;
  $("#outMeta").textContent = `${time} · ${ok}/${entries.length} succeeded`;
  $("#out").innerHTML = entries.map(([id,res])=>{
    const f = fws.find(x=>x.id===id) || {name:id};
    return `<div class="res ${res.ok?"":"fail"}"><div class="h">
      <span class="dot ${res.ok?"on":"off"}"></span><b>${esc(f.name)}</b>
      <span class="tag">${esc(f.host||"")}</span></div>
      <pre>${esc(resText(res))}${res.ok&&res.result?.download?
        `\n<a class="dl" href="${esc(res.result.download)}" download>⬇ Download config.xml</a>`:""}</pre></div>`;
  }).join("");
}

function fail(e){
  $("#outMeta").textContent = "";
  $("#out").innerHTML = `<div class="res fail"><pre>${esc(e.message)}</pre></div>`;
}

function needSel(){ if(!selected.size){ alert("Select at least one firewall."); return false;} return true; }

async function runCmd(){
  const command = $("#cmd").value.trim();
  if (!command || !needSel()) return;
  $("#runBtn").disabled = true;
  openOut(command);
  try { show(await post("/api/exec",{ids:[...selected],command}), command); }
  catch(e){ fail(e); }
  $("#runBtn").disabled = false;
}

async function doAction(a,label){
  if (!needSel()) return;
  if (a==="reboot" && !confirm(`Reboot ${selected.size} firewall(s)? Traffic through them will stop until they are back.`)) return;
  openOut(label + (a==="check-updates" ? " (can take a minute)" : ""));
  try { show(await post("/api/action",{ids:[...selected],action:a}), label); }
  catch(e){ fail(e); }
  if (a==="backup") loadBackups();
  if (a==="check-updates") loadStatus();
}

async function showLogs(){
  if (!needSel()) return;
  const log = $("#logName").value, lines = +$("#logLines").value, filter = $("#logFilter").value.trim();
  const label = `${$("#logName").selectedOptions[0].text} log · last ${lines}${filter?` · “${filter}”`:""}`;
  openOut(label);
  try { show(await post("/api/logs",{ids:[...selected],log,lines,filter}), label); }
  catch(e){ fail(e); }
}

// ------------------------------------------------------- firewall dialog
function syncMethod(){ $("#frm").classList.toggle("rest", $("#frm").elements.method.value==="rest"); }
function openDlg(f){
  editing = f?.id || null;
  const frm = $("#frm");
  frm.reset();
  if (f) for (const [k,v] of Object.entries(f)) {
    const el = frm.elements[k]; if (!el) continue;
    if (el.type==="checkbox") el.checked = !!v; else el.value = v ?? "";
  }
  frm.elements.password.placeholder = f ? "unchanged" : "";
  if (f) frm.elements.password.value = "";
  frm.elements.api_key.placeholder = f?.api_key ? "unchanged" : "";
  if (f) frm.elements.api_key.value = f.api_key ? "********" : "";
  $("#delBtn").hidden = !f;
  syncMethod();
  $("#dlg").showModal();
}
$("#frm").elements.method.onchange = syncMethod;

$("#frm").addEventListener("submit", async e=>{
  e.preventDefault();
  const frm = e.target, d = Object.fromEntries(new FormData(frm));
  d.verify_ssl = frm.elements.verify_ssl.checked;
  d.port = d.port ? +d.port : null;
  try {
    await api(editing?`/api/firewalls/${editing}`:"/api/firewalls",{method:editing?"PUT":"POST",body:JSON.stringify(d)});
    $("#dlg").close(); await loadFws(); loadStatus();
  } catch(err){ alert(err.message); }
});
$("#delBtn").onclick = async ()=>{
  if (!confirm("Remove this firewall from the fleet? (Nothing is changed on the firewall.)")) return;
  await api(`/api/firewalls/${editing}`,{method:"DELETE"}); selected.delete(editing);
  $("#dlg").close(); delete status[editing]; loadFws();
};
$("#cancel").onclick = ()=>$("#dlg").close();

// ------------------------------------------------------- users & SSH keys
let usrIds = [], usrAgg = new Map(), usrCur = null, usrGroups = [];

function keyParts(line){
  const t = line.trim().split(/\s+/);
  const i = t.findIndex(x=>x.length>40 && /^[A-Za-z0-9+/=]+$/.test(x));
  if (i<0) return {id:line.trim(), type:"?", comment:"", tail:""};
  return {id:t[i], type:t[i-1]||"", comment:t.slice(i+1).join(" "), tail:t[i].slice(-10)};
}
const keyLines = txt => (txt||"").split("\n").map(s=>s.trim()).filter(s=>s && !s.startsWith("#"));

async function openUsers(){
  if (!needSel()) return;
  usrIds = [...selected];
  $("#usrMeta").textContent = `${usrIds.length} firewall(s): ` + usrIds.map(id=>fws.find(f=>f.id===id)?.name).join(", ");
  if (!$("#usrDlg").open) $("#usrDlg").showModal();
  newUser();
  await loadUsers();
}

async function loadUsers(){
  $("#usrRows").innerHTML = `<tr><td colspan="4" class="hint"><span class="spin"></span>Loading users…</td></tr>`;
  $("#usrErr").textContent = "";
  let res;
  try { res = await post("/api/users/list",{ids:usrIds}); }
  catch(e){ $("#usrRows").innerHTML = ""; $("#usrErr").textContent = e.message; return; }
  usrAgg = new Map(); const grp = new Set(), errs = [];
  for (const [id,r] of Object.entries(res)) {
    const fname = fws.find(f=>f.id===id)?.name || id;
    if (!r.ok) { errs.push(`${fname}: ${r.error}`); continue; }
    r.result.groups.forEach(g=>grp.add(g));
    for (const u of r.result.users) {
      let a = usrAgg.get(u.name);
      if (!a) usrAgg.set(u.name, a = {name:u.name, descr:u.descr, uid:u.uid, scope:u.scope,
        fws:[], groups:new Set(), keys:new Map(), disabled:false, shell:false});
      a.fws.push(id);
      u.groups.forEach(g=>a.groups.add(g));
      if (u.disabled) a.disabled = true;
      if ((u.priv||[]).includes("user-shell-access")) a.shell = true;
      for (const l of keyLines(u.keys)) {
        const k = keyParts(l);
        const e = a.keys.get(k.id) || {...k, line:l, fws:[]};
        e.fws.push(id); a.keys.set(k.id, e);
      }
    }
  }
  usrGroups = [...grp].sort();
  $("#grpList").innerHTML = usrGroups.map(g=>`<option value="${esc(g)}">`).join("");
  $("#usrErr").textContent = errs.join("\n");
  renderUsers();
  if (usrCur) { const u = usrAgg.get(usrCur); u ? pickUser(u.name, true) : newUser(); }
}

function renderUsers(){
  const n = usrIds.length;
  $("#usrRows").innerHTML = [...usrAgg.values()].sort((a,b)=>a.name.localeCompare(b.name)).map(u=>
    `<tr data-u="${esc(u.name)}" class="${u.name===usrCur?"cur":""}">
      <td><span class="${u.disabled?"off":""}">${esc(u.name)}</span>${u.descr?` <span class="hint">${esc(u.descr)}</span>`:""}</td>
      <td title="${esc(u.fws.map(id=>fws.find(f=>f.id===id)?.name).join(", "))}">${u.fws.length}/${n}</td>
      <td>${[...u.groups].map(g=>`<span class="tag">${esc(g)}</span>`).join(" ")}${u.shell?` <span class="tag">shell</span>`:""}</td>
      <td class="num">${u.keys.size}</td></tr>`).join("")
    || `<tr><td colspan="4" class="hint">No users found.</td></tr>`;
}

function clearDirty(){ $("#usrFrm").querySelectorAll(".dirty").forEach(el=>el.classList.remove("dirty")); }

function newUser(){
  usrCur = null;
  const frm = $("#usrFrm"); frm.reset(); clearDirty();
  frm.elements.name.readOnly = false;
  $("#usrTitle").textContent = "New user";
  $("#pwHint").textContent = "(required for new users)";
  frm.elements.password.placeholder = "";
  $("#usrDel").hidden = true;
  $("#usrKeys").innerHTML = "";
  $("#dirtyHint").hidden = true;
  renderUsers();
}

function pickUser(name, keepForm){
  const u = usrAgg.get(name); if (!u) return;
  usrCur = name;
  const frm = $("#usrFrm");
  if (!keepForm) {
    frm.reset(); clearDirty();
    frm.elements.name.value = u.name;
    frm.elements.descr.value = u.descr || "";
    frm.elements.groups.value = [...u.groups].join(", ");
    frm.elements.shell.checked = u.shell;
    frm.elements.disabled.checked = u.disabled;
  }
  frm.elements.name.readOnly = true;
  $("#usrTitle").textContent = `Edit ${u.name}`;
  const missing = usrIds.length - u.fws.length;
  $("#pwHint").textContent = missing ? `(blank = keep; needed to create it on ${missing} firewall(s) that lack it)` : "(blank = keep)";
  frm.elements.password.placeholder = "unchanged";
  $("#usrDel").hidden = u.uid===0 || u.scope==="system";
  $("#dirtyHint").hidden = false;
  const n = usrIds.length;
  $("#usrKeys").innerHTML = [...u.keys.values()].map(k=>`<div class="k">
      <span title="${esc(k.line)}">${esc(k.type)} …${esc(k.tail)} <em>${esc(k.comment)}</em></span>
      <span class="hint" style="flex:none" title="${esc(k.fws.map(id=>fws.find(f=>f.id===id)?.name).join(", "))}">${k.fws.length}/${n}</span>
      <button type="button" class="link" data-rmkey="${esc(k.id)}" title="Remove this key from the selected firewalls">✕</button></div>`).join("")
    || `<span class="hint">No SSH keys.</span>`;
  renderUsers();
}

async function userCall(path, body, label){
  openOut(label, usrIds.length);
  try { show(await post(path, {ids:usrIds, ...body}), label); }
  catch(e){ fail(e); }
  await loadUsers();
}

$("#usrRows").addEventListener("click", e=>{ const tr = e.target.closest("tr[data-u]"); if (tr) pickUser(tr.dataset.u); });
$("#usrNew").onclick = newUser;
$("#usrReload").onclick = loadUsers;
$("#usrClose").onclick = ()=>$("#usrDlg").close();
$("#usersBtn").onclick = openUsers;
$("#usrFrm").addEventListener("input", e=>{ if (e.target.name && e.target.name!=="key_mode") e.target.classList.add("dirty"); });
$("#usrFrm").addEventListener("change", e=>{ if (e.target.type==="checkbox") e.target.classList.add("dirty"); });

$("#usrFrm").addEventListener("submit", async e=>{
  e.preventDefault();
  const frm = e.target, isNew = !usrCur;
  const dirty = n => isNew || frm.elements[n].classList.contains("dirty");
  const spec = {name: frm.elements.name.value.trim(), key_mode: frm.elements.key_mode.value};
  if (frm.elements.password.value) spec.password = frm.elements.password.value;
  if (dirty("descr")) spec.descr = frm.elements.descr.value;
  if (dirty("groups")) spec.groups = frm.elements.groups.value.split(",").map(s=>s.trim()).filter(Boolean);
  if (dirty("shell")) spec.shell = frm.elements.shell.checked;
  if (dirty("disabled")) spec.disabled = frm.elements.disabled.checked;
  const keys = frm.elements.keys.value.trim();
  if (keys || (spec.key_mode==="replace" && dirty("keys"))) spec.keys = keys;
  if (spec.key_mode==="replace" && spec.keys!==undefined && !keys &&
      !confirm(`Remove ALL SSH keys of ${spec.name} on ${usrIds.length} firewall(s)?`)) return;
  if (isNew && !spec.password) { alert("A password is required for a new user."); return; }
  if (Object.keys(spec).length <= 2) { alert("Nothing changed."); return; }
  const verb = isNew ? "Create" : "Update";
  if (!confirm(`${verb} user ${spec.name} on ${usrIds.length} firewall(s)?`)) return;
  usrCur = spec.name;
  await userCall("/api/users/set", {user:spec}, `${verb} user ${spec.name}`);
  frm.elements.password.value = ""; frm.elements.keys.value = ""; clearDirty();
  if (usrAgg.has(spec.name)) pickUser(spec.name);
});

$("#usrDel").onclick = async ()=>{
  const name = usrCur; if (!name) return;
  if (!confirm(`Delete user ${name} from ${usrIds.length} firewall(s)? This also removes its SSH keys and home directory.`)) return;
  usrCur = null;
  await userCall("/api/users/delete", {name}, `Delete user ${name}`);
  newUser();
};

$("#usrKeys").addEventListener("click", async e=>{
  const id = e.target.dataset.rmkey; if (!id || !usrCur) return;
  const k = usrAgg.get(usrCur).keys.get(id);
  if (!confirm(`Remove key ${k.type} …${k.tail} ${k.comment} from ${usrCur} on ${k.fws.length} firewall(s)?`)) return;
  const name = usrCur;
  await userCall("/api/users/set", {user:{name, keys:k.line, key_mode:"remove"}}, `Remove SSH key from ${name}`);
  pickUser(name);
});

// ------------------------------------------------------------ wiring
$("#addBtn").onclick = ()=>openDlg(null);
$("#refresh").onclick = loadStatus;
$("#runBtn").onclick = runCmd;
$("#logBtn").onclick = showLogs;
$("#logFilter").addEventListener("keydown", e=>{ if(e.key==="Enter") showLogs(); });
// Popup size: drag the bottom-right corner to resize; size is remembered
(() => {
  const d = $("#outDlg");
  try { const s = JSON.parse(localStorage.getItem("outSize")||"null");
        if (s) { d.style.width = s.w+"px"; d.style.height = s.h+"px"; } } catch {}
  new ResizeObserver(() => {
    if (!d.open || d.classList.contains("max")) return;
    try { localStorage.setItem("outSize", JSON.stringify({w:d.offsetWidth, h:d.offsetHeight})); } catch {}
  }).observe(d);
  $("#outMax").onclick = () => d.classList.toggle("max");
})();
$("#outClose").onclick = ()=>$("#outDlg").close();
// Close on a genuine backdrop click only: press AND release outside the popup,
// so finishing a resize drag doesn't close it
for (const d of [$("#outDlg"), $("#usrDlg")]) {
  const outside = e => { const r = d.getBoundingClientRect();
    return e.clientX<r.left || e.clientX>r.right || e.clientY<r.top || e.clientY>r.bottom; };
  let downOutside = false;
  d.addEventListener("mousedown", e => { downOutside = e.target === d && outside(e); });
  d.addEventListener("click", e => { if (downOutside && e.target === d && outside(e)) d.close(); downOutside = false; });
}
$("#lastOut").onclick = ()=>{ if (lastResults){ render_out(); $("#outDlg").showModal(); } };
$("#outCopy").onclick = async ()=>{
  if (!lastResults) return;
  const txt = Object.entries(lastResults.results).map(([id,res])=>{
    const f = fws.find(x=>x.id===id) || {name:id};
    return `=== ${f.name} (${f.host||""}) ===\n${res.ok?resText(res):"ERROR: "+res.error}`;
  }).join("\n\n");
  let ok = false;
  try { await navigator.clipboard.writeText(txt); ok = true; }
  catch { // clipboard API needs HTTPS; fall back for plain http://IP access
    const t = document.createElement("textarea"); t.value = txt;
    $("#outDlg").appendChild(t); t.select();
    try { ok = document.execCommand("copy"); } catch {}
    t.remove();
  }
  $("#outCopy").textContent = ok ? "copied" : "copy failed";
  setTimeout(()=>$("#outCopy").textContent="copy all", 1500);
};
$("#groupFilter").onchange = render;
$("#cmd").addEventListener("keydown", e=>{ if(e.key==="Enter"&&(e.ctrlKey||e.metaKey)) runCmd(); });
$("#rows").addEventListener("click", e=>{
  const s = e.target.dataset.sel, ed = e.target.dataset.edit;
  if (s) { e.target.checked ? selected.add(s) : selected.delete(s); render(); }
  if (ed) openDlg(fws.find(f=>f.id===ed));
});
$("#selAll").onchange = e=>{
  const g = $("#groupFilter").value;
  fws.filter(f=>!g||f.group===g).forEach(f=> e.target.checked?selected.add(f.id):selected.delete(f.id));
  render();
};
$("#qa").addEventListener("click", e=>{ const a=e.target.dataset.a; if(a) doAction(a, e.target.textContent); });
const kb = n => n>1048576 ? (n/1048576).toFixed(1)+" MB" : Math.max(1,Math.round(n/1024))+" KB";
async function loadBackups(){
  let list=[]; try { list = await api("/api/backups"); } catch(e){}
  $("#bk").innerHTML = list.length ? list.map(b=>`<div class="it">
    <div class="nm"><b>${esc(b.firewall)}</b><div title="${esc(b.file)}">${esc(b.file)}</div>
      <span class="hint">${new Date(b.mtime*1000).toLocaleString()} · ${kb(b.size)}</span></div>
    <a class="dl" href="${esc(b.url)}" download>Download</a>
    <button class="link" data-delbk="${esc(b.url)}">✕</button></div>`).join("")
    : `<div class="hint" style="padding:12px 14px">No backups yet. Select firewalls and click <b>Save backup</b>.</div>`;
}
$("#bk").addEventListener("click", async e=>{
  const u = e.target.dataset.delbk; if(!u || !confirm("Delete this backup from the server?")) return;
  await api(u,{method:"DELETE"}); loadBackups();
});
$("#bkRefresh").onclick = loadBackups;
function setThemeIcon(){
  const light = document.documentElement.dataset.theme === "light";
  $("#themeBtn").textContent = light ? "☾" : "☀";
  $("#themeBtn").title = light ? "Switch to dark mode" : "Switch to light mode";
}
$("#themeBtn").onclick = () => {
  const t = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("theme", t); } catch {}
  setThemeIcon();
};
setThemeIcon();
function schedule(){ clearInterval(timer); if($("#auto").checked) timer=setInterval(loadStatus,30000); }
$("#auto").onchange = schedule;

api("/api/logs").then(l => $("#logName").innerHTML =
  Object.entries(l).map(([k,v])=>`<option value="${k}">${esc(v)}</option>`).join("")).catch(()=>{});
loadFws().then(loadStatus); loadBackups(); schedule();
