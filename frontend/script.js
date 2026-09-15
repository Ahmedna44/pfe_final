const SERVER_HOST = window.location.hostname || 'localhost';
const API = `http://${SERVER_HOST}:5000`;
const CLIENT = `http://${SERVER_HOST}:8080`;
 
const user = JSON.parse(localStorage.getItem('ids_user') || 'null');
if (!user) location.href = 'login.html';
 
document.getElementById('userName').textContent = user.nom + ' (' + user.code + ')';
document.getElementById('userRole').textContent = 'ADMIN';
 
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  document.getElementById(t.dataset.tab).classList.add('active');
  if (t.dataset.tab === 'dashboard') loadStats();
  if (t.dataset.tab === 'historique') loadHistory();
  if (t.dataset.tab === 'profils') loadProfiles();
});
 
function logout() {
  localStorage.removeItem('ids_user');
  location.href = 'login.html';
}
 
async function checkBackend() {
  try {
    await fetch(API + '/');
    document.getElementById('backendStatus').textContent = '● BACKEND EN LIGNE';
    document.getElementById('backendStatus').className = 'status';
  } catch (e) {
    document.getElementById('backendStatus').textContent = '● BACKEND HORS LIGNE';
    document.getElementById('backendStatus').className = 'status off';
  }
}
setInterval(checkBackend, 5000);
checkBackend();
 
function notif(msg) {
  const d = document.createElement('div');
  d.className = 'notif';
  d.textContent = msg;
  document.getElementById('notifs').appendChild(d);
  setTimeout(() => d.remove(), 4000);
}
 
let lastAttackTimestamp = '';
let popupQueue = [];
let popupShowing = false;
 
function showAttackPopup(attack) {
  popupQueue.push(attack);
  if (!popupShowing) processPopupQueue();
}
 
function processPopupQueue() {
  if (popupQueue.length === 0) {
    popupShowing = false;
    return;
  }
  popupShowing = true;
  const attack = popupQueue.shift();
 
  const popup = document.getElementById('attackPopup');
  if (!popup) {
    popupShowing = false;
    return;
  }
 
  const type = (attack.attack_type || 'INCONNUE').toUpperCase();
  const time = (attack.timestamp || '').split(' ')[1] || '';
  const srcIp = attack.src_ip || 'inconnue';
 
  popup.innerHTML = `
    <div class="popup-content">
      <div class="popup-header">
        <span class="popup-icon">🚨</span>
        <span class="popup-title">ATTAQUE DÉTECTÉE !</span>
        <button class="popup-close" onclick="closeAttackPopup()">×</button>
      </div>
      <div class="popup-body">
        <div class="popup-row"><strong>Type :</strong> <span class="badge ${attack.attack_type}">${type}</span></div>
        <div class="popup-row"><strong>Source :</strong> <code>${srcIp}</code></div>
        <div class="popup-row"><strong>Heure :</strong> ${time}</div>
      </div>
      <div class="popup-footer">
        <small>📧 Un email d'alerte a été envoyé à l'administrateur</small>
      </div>
    </div>
  `;
  popup.classList.add('show');
 
  // Beep d'alerte
  try {
    const audio = new AudioContext();
    const osc = audio.createOscillator();
    const gain = audio.createGain();
    osc.connect(gain);
    gain.connect(audio.destination);
    osc.frequency.value = 880;
    osc.type = 'square';
    gain.gain.setValueAtTime(0.1, audio.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audio.currentTime + 0.3);
    osc.start();
    osc.stop(audio.currentTime + 0.3);
  } catch (e) {}
 
  setTimeout(() => {
    closeAttackPopup();
    setTimeout(processPopupQueue, 500);
  }, 5000);
}
 
function closeAttackPopup() {
  const popup = document.getElementById('attackPopup');
  if (popup) popup.classList.remove('show');
}
 
async function pollAttacks() {
  try {
    const url = lastAttackTimestamp
      ? `${API}/recent_attacks?since=${encodeURIComponent(lastAttackTimestamp)}`
      : `${API}/recent_attacks`;
    const r = await fetch(url);
    const attacks = await r.json();
 
    if (attacks.length > 0) {
      if (!lastAttackTimestamp) {
        lastAttackTimestamp = attacks[attacks.length - 1].timestamp;
        return;
      }
      attacks.forEach(a => showAttackPopup(a));
      lastAttackTimestamp = attacks[attacks.length - 1].timestamp;
    }
  } catch (e) {}
}
 
setInterval(pollAttacks, 3000);
pollAttacks();
 
async function loadStats() {
  try {
    const r = await fetch(API + '/stats');
    const s = await r.json();
    document.getElementById('statTotal').textContent = s.total;
    document.getElementById('statNormal').textContent = s.normal;
    document.getElementById('statAttacks').textContent = s.attacks;
    document.getElementById('statRate').textContent = s.attack_rate + '%';
    document.getElementById('statNormalPct').textContent = s.total ? (100 * s.normal / s.total).toFixed(1) + '%' : '0%';
    document.getElementById('statAttacksPct').textContent = s.attack_rate + '%';
    drawPie(s.normal, s.attacks);
    drawFamilies(s.by_family);
    drawProtos(s.by_protocol);
    drawServices(s.top_services);
    drawRecent(s.recent);
  } catch (e) {
    notif('Erreur chargement stats');
  }
}
 
function drawPie(normal, attacks) {
  const c = document.getElementById('pieChart');
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, 300, 220);
  const total = normal + attacks;
  if (!total) return;
  const cx = 150, cy = 110, r = 80;
  let start = -Math.PI / 2;
  [[normal, '#2ecc71'], [attacks, '#ff4757']].forEach(([v, col]) => {
    const end = start + (v / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, end);
    ctx.fillStyle = col;
    ctx.fill();
    start = end;
  });
  document.getElementById('pieLegend').innerHTML =
    `<div class="legend-item"><span class="legend-dot" style="background:#2ecc71"></span>Normal: ${normal} (${total ? (100 * normal / total).toFixed(1) : 0}%)</div>
     <div class="legend-item"><span class="legend-dot" style="background:#ff4757"></span>Attaques: ${attacks} (${total ? (100 * attacks / total).toFixed(1) : 0}%)</div>
     <div class="legend-item"><span class="legend-dot" style="background:#00d4ff"></span>Total: ${total}</div>`;
}
 
function drawFamilies(f) {
  const max = Math.max(1, ...Object.values(f));
  const colors = { dos: '#ff4757', probe: '#f39c12', r2l: '#9b59b6', u2r: '#3498db' };
  document.getElementById('familyBars').innerHTML = Object.entries(f).map(([k, v]) =>
    `<div class="family-bar">
       <span class="family-name">${k.toUpperCase()}</span>
       <div class="family-fill" style="background:${colors[k]};width:${Math.max(40, (v / max) * 100)}%">${v}</div>
     </div>`).join('');
}
 
function drawProtos(p) {
  const html = Object.entries(p).map(([k, v]) =>
    `<div class="proto-line"><span>${k}</span><span style="color:#00d4ff">${v}</span></div>`).join('');
  document.getElementById('protoList').innerHTML = html || '<div style="color:#6b7a99;font-size:11px">Aucun</div>';
}
 
function drawServices(s) {
  const html = s.map(x =>
    `<div class="svc-line"><span>${x.service}</span><span style="color:#00d4ff">${x.count}</span></div>`).join('');
  document.getElementById('serviceList').innerHTML = html || '<div style="color:#6b7a99;font-size:11px">Aucun</div>';
}
 
function drawRecent(rows) {
  const html = rows.map(r => {
    const time = (r.timestamp || '').split(' ')[1] || '';
    const det = `<span class="badge ${r.detection === 'NORMAL' ? 'normal' : 'attack'}">${r.detection}</span>`;
    const typ = r.attack_type ? `<span class="badge ${r.attack_type}">${r.attack_type.toUpperCase()}</span>` : '—';
    return `<tr><td>${time}</td><td>${det}</td><td>${typ}</td><td>${r.protocol}</td></tr>`;
  }).join('');
  document.getElementById('recentDetections').innerHTML = html ||
    '<tr><td colspan="4" style="color:#6b7a99;text-align:center;padding:20px">Aucune détection</td></tr>';
}
 
async function simulateAttack(family) {
  logTerminal(`\n=== SIMULATION ${family.toUpperCase()} ===`);
  logTerminal(`-> Chargement d'un échantillon NSL-KDD (famille: ${family})`);
 
  try {
    const r = await fetch(API + '/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ family: family })
    });
    const result = await r.json();
 
    if (result.detection === 'NORMAL') {
      logTerminal(`Verdict : TRAFIC NORMAL`);
    } else {
      const type = (result.attack_type || 'inconnu').toUpperCase();
      logTerminal(`🚨 ATTAQUE DÉTECTÉE - Type: ${type}`);
      logTerminal(`   Service: ${result.service} | Protocole: ${result.protocol}`);
    }
    setTimeout(loadStats, 500);
  } catch (e) {
    logTerminal(`Erreur: serveur (port 5000) inaccessible`);
    logTerminal(`   -> Lance : python app.py`);
    notif('Serveur non démarré');
  }
}
 
async function analyseManual() {
  const data = {
    timestamp: new Date().toISOString(),
    src_ip: 'manual_analysis',
    duration: +document.getElementById('f_duration').value,
    protocol_type: document.getElementById('f_protocol_type').value,
    service: document.getElementById('f_service').value,
    flag: document.getElementById('f_flag').value,
    src_bytes: +document.getElementById('f_src_bytes').value,
    dst_bytes: +document.getElementById('f_dst_bytes').value,
    count: +document.getElementById('f_count').value,
    srv_count: +document.getElementById('f_srv_count').value,
    serror_rate: +document.getElementById('f_serror_rate').value,
    land: 0, wrong_fragment: 0, urgent: 0, hot: 0,
    num_failed_logins: 0, logged_in: 0, num_compromised: 0,
    root_shell: 0, su_attempted: 0, num_root: 0,
    num_file_creations: 0, num_shells: 0, num_access_files: 0,
    num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
    srv_serror_rate: 0, rerror_rate: 0, srv_rerror_rate: 0,
    same_srv_rate: 1.0, diff_srv_rate: 0, srv_diff_host_rate: 0,
    dst_host_count: 1, dst_host_srv_count: 1,
    dst_host_same_srv_rate: 1.0, dst_host_diff_srv_rate: 0,
    dst_host_same_src_port_rate: 1.0, dst_host_srv_diff_host_rate: 0,
    dst_host_serror_rate: 0, dst_host_srv_serror_rate: 0,
    dst_host_rerror_rate: 0, dst_host_srv_rerror_rate: 0,
  };
 
  logTerminal(`\n=== ANALYSE MANUELLE ===`);
  try {
    const r = await fetch(API + '/api/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const res = await r.json();
    logTerminal(`Détection : ${res.detection}`);
    if (res.attack_type) logTerminal(`Type : ${res.attack_type.toUpperCase()}`);
    setTimeout(loadStats, 500);
  } catch (e) {
    logTerminal(`Erreur: serveur inaccessible`);
  }
}
 
function logTerminal(txt) {
  const t = document.getElementById('terminal');
  if (!t) return;
  if (t.textContent.startsWith('Lance')) t.textContent = '';
  t.textContent += txt + '\n';
  t.scrollTop = t.scrollHeight;
}
 
function clearTerminal() {
  const t = document.getElementById('terminal');
  if (t) t.textContent = 'Terminal effacé.\n';
}
 
async function loadHistory() {
  try {
    const r = await fetch(API + '/history?limit=10000');
    const rows = await r.json();
    const html = rows.map(d => renderRow(d)).join('');
    document.getElementById('historyBody').innerHTML = html ||
      '<tr><td colspan="6" style="color:#6b7a99;text-align:center;padding:20px">Aucune détection enregistrée</td></tr>';
  } catch (e) {
    notif('Erreur chargement historique');
  }
}
 
function renderRow(d) {
  const det = `<span class="badge ${d.detection === 'NORMAL' ? 'normal' : 'attack'}">${d.detection}</span>`;
  const typ = d.attack_type ? `<span class="badge ${d.attack_type}">${d.attack_type.toUpperCase()}</span>` : '—';
  return `<tr>
    <td>${d.id}</td>
    <td>${d.timestamp}</td>
    <td>${det}</td>
    <td>${typ}</td>
    <td>${d.protocol}</td>
    <td>${d.service}</td>
  </tr>`;
}
 
async function resetHistory() {
  if (!confirm('Vider tout l\'historique ?')) return;
  try {
    await fetch(API + '/history/clear', { method: 'POST' });
    loadHistory();
    loadStats();
    notif('Historique vidé');
  } catch (e) {
    notif('Erreur');
  }
}
 
async function loadProfiles() {
  try {
    const r = await fetch(API + '/profiles');
    const rows = await r.json();
    document.getElementById('profilesBody').innerHTML = rows.map(p =>
      `<tr>
        <td>${p.code}</td>
        <td>${p.nom}</td>
        <td>${p.username}</td>
        <td>${p.created_at}</td>
        <td>${p.code !== 'ADM001' ? `<button class="btn-del" onclick="deleteProfile('${p.code}')">Supprimer</button>` : '—'}</td>
      </tr>`).join('');
  } catch (e) {
    notif('Erreur chargement profils');
  }
}
 
async function createProfile() {
  const p = {
    code: document.getElementById('p_code').value,
    nom: document.getElementById('p_nom').value,
    username: document.getElementById('p_user').value,
    password: document.getElementById('p_pass').value,
  };
  if (!p.code || !p.nom || !p.username || !p.password) {
    notif('Champs manquants');
    return;
  }
  try {
    const r = await fetch(API + '/profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(p)
    });
    const d = await r.json();
    if (r.ok) {
      notif('Profil créé');
      loadProfiles();
      ['p_code', 'p_nom', 'p_user', 'p_pass'].forEach(i => document.getElementById(i).value = '');
    } else {
      notif(d.error || 'Erreur');
    }
  } catch (e) {
    notif('Erreur réseau');
  }
}
 
async function deleteProfile(code) {
  if (!confirm(`Supprimer ${code} ?`)) return;
  try {
    await fetch(API + '/profiles/' + code, { method: 'DELETE' });
    loadProfiles();
    notif('Profil supprimé');
  } catch (e) {
    notif('Erreur');
  }
}
 
loadStats();
setInterval(() => {
  if (document.getElementById('dashboard').classList.contains('active')) loadStats();
  if (document.getElementById('historique').classList.contains('active')) loadHistory();
}, 5000);
 