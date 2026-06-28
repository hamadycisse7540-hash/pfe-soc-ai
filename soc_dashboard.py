<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC IP Management Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: "Segoe UI", monospace, sans-serif; background: #0a0e1a; color: #e2e8f0; min-height: 100vh; }
  header { background: linear-gradient(135deg, #0d1b2a, #1a2744); border-bottom: 1px solid #00d4ff33; padding: 16px 28px; display: flex; align-items: center; justify-content: space-between; }
  .logo { display: flex; align-items: center; gap: 12px; }
  .logo-icon { width: 38px; height: 38px; background: #00d4ff22; border: 1px solid #00d4ff55; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
  .logo-text h1 { font-size: 1rem; color: #00d4ff; font-weight: 700; letter-spacing: 1px; }
  .logo-text p { font-size: 0.7rem; color: #64748b; margin-top: 2px; }
  .status-bar { display: flex; gap: 16px; align-items: center; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .status-text { font-size: 0.75rem; color: #94a3b8; }
  .main { padding: 24px 28px; max-width: 1200px; margin: 0 auto; }
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat-card { background: #0d1b2a; border: 1px solid #1e3a5f; border-radius: 10px; padding: 18px; position: relative; overflow: hidden; }
  .stat-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
  .stat-card.red::before { background: #dc3545; }
  .stat-card.orange::before { background: #fd7e14; }
  .stat-card.blue::before { background: #0d6efd; }
  .stat-card.green::before { background: #198754; }
  .stat-label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .stat-value { font-size: 2rem; font-weight: 700; font-family: monospace; }
  .stat-card.red .stat-value { color: #ff6b7a; }
  .stat-card.orange .stat-value { color: #ffa94d; }
  .stat-card.blue .stat-value { color: #74b9ff; }
  .stat-card.green .stat-value { color: #55efc4; }
  .stat-sub { font-size: 0.7rem; color: #475569; margin-top: 4px; }
  .panel { background: #0d1b2a; border: 1px solid #1e3a5f; border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
  .panel-header { padding: 14px 20px; border-bottom: 1px solid #1e3a5f; display: flex; align-items: center; justify-content: space-between; }
  .panel-title { font-size: 0.85rem; font-weight: 600; color: #cbd5e1; }
  .panel-badge { background: #dc354522; color: #ff6b7a; border: 1px solid #dc354544; padding: 2px 8px; border-radius: 20px; font-size: 0.7rem; margin-left: 8px; }
  .ip-table { width: 100%; border-collapse: collapse; }
  .ip-table th { padding: 10px 16px; text-align: left; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; color: #475569; border-bottom: 1px solid #1e3a5f; }
  .ip-table td { padding: 12px 16px; font-size: 0.82rem; border-bottom: 1px solid #0f2035; }
  .ip-table tr:hover td { background: #0f2035; }
  .ip-addr { font-family: monospace; color: #00d4ff; font-weight: 600; }
  .sev-badge { padding: 3px 10px; border-radius: 20px; font-size: 0.7rem; font-weight: 600; }
  .sev-critique { background: #dc354522; color: #ff6b7a; border: 1px solid #dc354544; }
  .action-btn { padding: 4px 12px; border-radius: 6px; border: none; cursor: pointer; font-size: 0.75rem; font-weight: 600; transition: all 0.2s; }
  .btn-unblock { background: #19875422; color: #55efc4; border: 1px solid #19875444; }
  .btn-unblock:hover { background: #19875488; }
  .btn-info { background: #0d6efd22; color: #74b9ff; border: 1px solid #0d6efd44; margin-left: 4px; text-decoration: none; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
  .empty-state { padding: 40px; text-align: center; color: #475569; }
  .empty-state .icon { font-size: 2.5rem; margin-bottom: 10px; }
  .input-row { display: flex; gap: 10px; padding: 16px 20px; }
  .ip-input { flex: 1; background: #0a0e1a; border: 1px solid #1e3a5f; border-radius: 8px; padding: 10px 14px; color: #e2e8f0; font-family: monospace; font-size: 0.85rem; outline: none; }
  .ip-input::placeholder { color: #334155; }
  .btn-block { background: #dc354522; color: #ff6b7a; border: 1px solid #dc354544; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-size: 0.82rem; font-weight: 600; }
  .btn-block:hover { background: #dc354588; }
  .btn-refresh { background: #0d6efd22; color: #74b9ff; border: 1px solid #0d6efd44; padding: 10px 16px; border-radius: 8px; cursor: pointer; font-size: 0.82rem; }
  .alert-log { max-height: 200px; overflow-y: auto; padding: 0 20px 16px; }
  .log-entry { padding: 8px 0; border-bottom: 1px solid #0f2035; font-size: 0.78rem; display: flex; gap: 10px; }
  .log-time { color: #475569; font-family: monospace; white-space: nowrap; }
  .log-ok { color: #55efc4; }
  .log-warn { color: #ffa94d; }
  .log-err { color: #ff6b7a; }
  .log-msg { color: #94a3b8; }
  .api-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 16px 20px; }
  .api-item { background: #0a0e1a; border: 1px solid #1e3a5f; border-radius: 8px; padding: 12px 14px; }
  .api-method { font-size: 0.65rem; font-weight: 700; padding: 2px 6px; border-radius: 4px; margin-right: 6px; }
  .get { background: #19875422; color: #55efc4; }
  .post { background: #fd7e1422; color: #ffa94d; }
  .api-path { font-family: monospace; font-size: 0.78rem; color: #e2e8f0; }
  .api-desc { font-size: 0.7rem; color: #475569; margin-top: 4px; }
  .toast { position: fixed; bottom: 20px; right: 20px; padding: 12px 20px; border-radius: 8px; font-size: 0.82rem; font-weight: 600; opacity: 0; transition: opacity 0.3s; z-index: 999; }
  .toast.show { opacity: 1; }
  .toast-ok { background: #198754; color: white; }
  .toast-err { background: #dc3545; color: white; }
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">&#x1F6E1;</div>
    <div class="logo-text">
      <h1>SOC IP MANAGEMENT</h1>
      <p>AI Empowered Detection as Code &mdash; PFE 2026 | Wazuh v4.7.5</p>
    </div>
  </div>
  <div class="status-bar">
    <div class="status-dot"></div>
    <span class="status-text" id="api-status">Connexion...</span>
    <span class="status-text" style="color:#334155">|</span>
    <span class="status-text" id="clock"></span>
  </div>
</header>
<div class="main">
  <div class="stats-grid">
    <div class="stat-card red">
      <div class="stat-label">IPs Bloquees</div>
      <div class="stat-value" id="stat-blocked">-</div>
      <div class="stat-sub">actuellement actives</div>
    </div>
    <div class="stat-card orange">
      <div class="stat-label">Attaques detectees</div>
      <div class="stat-value" id="stat-attacks">-</div>
      <div class="stat-sub">cette session</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">IP la plus active</div>
      <div class="stat-value" style="font-size:0.95rem;padding-top:6px" id="stat-topip">-</div>
      <div class="stat-sub">source principale</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Regles LLM</div>
      <div class="stat-value" id="stat-rules">-</div>
      <div class="stat-sub">deployees sur Wazuh</div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">&#x1F6AB; IPs Bloquees <span class="panel-badge" id="blocked-count">0</span></div>
      <button class="btn-refresh" onclick="loadBlocked()">&#x21BB; Actualiser</button>
    </div>
    <div class="input-row">
      <input class="ip-input" id="manual-ip" placeholder="Entrer une IP a bloquer manuellement (ex: 192.168.1.158)" />
      <button class="btn-block" onclick="blockManual()">&#x1F512; Bloquer</button>
    </div>
    <div id="blocked-list">
      <div class="empty-state"><div class="icon">&#x2705;</div><div>Aucune IP bloquee actuellement</div></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">&#x1F4CB; Journal d activite</div>
    </div>
    <div class="alert-log" id="log-container">
      <div class="log-entry"><span class="log-time">--:--:--</span><span class="log-msg">Initialisation...</span></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">&#x1F50C; Endpoints API Flask</div>
    </div>
    <div class="api-grid">
      <div class="api-item"><span class="api-method get">GET</span><span class="api-path">/api/blocked</span><div class="api-desc">IPs bloquees iptables</div></div>
      <div class="api-item"><span class="api-method get">GET</span><span class="api-path">/api/stats</span><div class="api-desc">Statistiques detection</div></div>
      <div class="api-item"><span class="api-method get">GET</span><span class="api-path">/api/top-ips</span><div class="api-desc">Top IPs attaquantes</div></div>
      <div class="api-item"><span class="api-method post">POST</span><span class="api-path">/api/block/&lt;ip&gt;</span><div class="api-desc">Blocage manuel analyste</div></div>
      <div class="api-item"><span class="api-method post">POST</span><span class="api-path">/api/unblock/&lt;ip&gt;</span><div class="api-desc">Deblocage analyste SOC</div></div>
      <div class="api-item"><span class="api-method get">GET</span><span class="api-path">/api/rules-count</span><div class="api-desc">Regles LLM actives</div></div>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
var logs=[];
function addLog(msg,type){var t=new Date().toLocaleTimeString("fr-FR");logs.unshift({t:t,msg:msg,type:type||"msg"});if(logs.length>50)logs.pop();document.getElementById("log-container").innerHTML=logs.map(function(l){return'<div class="log-entry"><span class="log-time">'+l.t+'</span><span class="log-'+l.type+'">'+l.msg+'</span></div>';}).join("");}
function toast(msg,ok){var t=document.getElementById("toast");t.textContent=msg;t.className="toast "+(ok!==false?"toast-ok":"toast-err")+" show";setTimeout(function(){t.classList.remove("show");},3000);}
function loadBlocked(){fetch("/api/blocked").then(function(r){return r.json();}).then(function(d){var ips=d.blocked_ips||[];document.getElementById("stat-blocked").textContent=ips.length;document.getElementById("blocked-count").textContent=ips.length;var el=document.getElementById("blocked-list");if(!ips.length){el.innerHTML='<div class="empty-state"><div class="icon">&#x2705;</div><div>Aucune IP bloquee</div></div>';return;}el.innerHTML='<table class="ip-table"><tr><th>IP Source</th><th>Severite</th><th>Info</th><th>Action</th></tr>'+ips.map(function(ip){return'<tr><td><span class="ip-addr">'+ip+'</span></td><td><span class="sev-badge sev-critique">CRITIQUE</span></td><td><a href="https://ipinfo.io/'+ip+'" target="_blank" class="btn-info">&#x1F50D; ipinfo</a></td><td><button class="action-btn btn-unblock" onclick="unblock(\''+ip+'\')">&#x2705; Debloquer</button></td></tr>';}).join("")+'</table>';addLog(ips.length+" IP(s) bloquee(s)","warn");}).catch(function(e){addLog("Erreur blocked: "+e.message,"err");});}
function loadStats(){fetch("/api/stats").then(function(r){return r.json();}).then(function(d){document.getElementById("stat-attacks").textContent=d.attaques||0;var top=Object.entries(d.top_ip||{})[0];document.getElementById("stat-topip").textContent=top?top[0]:"N/A";document.getElementById("api-status").textContent="API Flask connectee";addLog("Stats chargees","ok");}).catch(function(e){document.getElementById("api-status").textContent="API inaccessible";addLog("Erreur stats: "+e.message,"err");});}
function loadRules(){fetch("/api/rules-count").then(function(r){return r.json();}).then(function(d){document.getElementById("stat-rules").textContent=d.count||0;}).catch(function(){document.getElementById("stat-rules").textContent="?";}); }
function unblock(ip){fetch("/api/unblock/"+ip,{method:"POST"}).then(function(r){return r.json();}).then(function(d){if(d.status==="success"){toast("IP "+ip+" debloquee");addLog("IP "+ip+" debloquee par analyste SOC","ok");loadBlocked();}else{toast(d.error||"Erreur",false);}}).catch(function(e){toast("Erreur connexion",false);});}
function blockManual(){var ip=document.getElementById("manual-ip").value.trim();if(!/^\d+\.\d+\.\d+\.\d+$/.test(ip)){toast("IP invalide",false);return;}fetch("/api/block/"+ip,{method:"POST"}).then(function(r){return r.json();}).then(function(d){if(d.status==="success"){toast("IP "+ip+" bloquee");addLog("IP "+ip+" bloquee manuellement","warn");document.getElementById("manual-ip").value="";loadBlocked();}else{toast(d.error||"Erreur",false);}}).catch(function(e){toast("Erreur connexion",false);});}
function updateClock(){document.getElementById("clock").textContent=new Date().toLocaleString("fr-FR");}
function init(){updateClock();setInterval(updateClock,1000);loadStats();loadBlocked();loadRules();setInterval(function(){loadBlocked();loadStats();loadRules();},15000);addLog("Dashboard SOC initialise","ok");}
init();
</script>
</body>
</html>