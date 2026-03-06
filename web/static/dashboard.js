let trafficChart;
let attackChart;
let serverChart;

const trafficLabels = [];
const trafficData = [];

function createCharts() {
  const trafficCtx = document.getElementById("trafficChart").getContext("2d");
  trafficChart = new Chart(trafficCtx, {
    type: "line",
    data: {
      labels: trafficLabels,
      datasets: [{
        label: "Bandwidth (Mbps)",
        data: trafficData,
        borderColor: "#0d6b4d",
        backgroundColor: "rgba(13, 107, 77, 0.15)",
        tension: 0.3,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
    },
  });

  const attackCtx = document.getElementById("attackChart").getContext("2d");
  attackChart = new Chart(attackCtx, {
    type: "bar",
    data: {
      labels: [],
      datasets: [{
        label: "Detected Attacks",
        data: [],
        backgroundColor: "#a12f35",
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
    },
  });

  const serverCtx = document.getElementById("serverChart").getContext("2d");
  serverChart = new Chart(serverCtx, {
    type: "doughnut",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: ["#0d6b4d", "#3f5b4f", "#91b7a2", "#cadfcf"],
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
    },
  });
}

function renderList(id, items, formatter) {
  const list = document.getElementById(id);
  list.innerHTML = "";
  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No data";
    list.appendChild(li);
    return;
  }
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = formatter(item);
    list.appendChild(li);
  });
}

async function fetchStatus() {
  const response = await fetch("/network/status");
  return await response.json();
}

async function fetchAttacks() {
  const response = await fetch("/attacks");
  return await response.json();
}

function updateTrafficChart(bandwidth) {
  const now = new Date().toLocaleTimeString();
  trafficLabels.push(now);
  trafficData.push(Number(bandwidth || 0));
  if (trafficLabels.length > 15) {
    trafficLabels.shift();
    trafficData.shift();
  }
  trafficChart.update();
}

function updateAttackChart(attacks) {
  const grouped = {};
  (attacks || []).forEach((event) => {
    const key = String(event.timestamp || "unknown").slice(11, 19);
    grouped[key] = (grouped[key] || 0) + 1;
  });

  attackChart.data.labels = Object.keys(grouped);
  attackChart.data.datasets[0].data = Object.values(grouped);
  attackChart.update();
}

function updateServerChart(servers) {
  const labels = [];
  const values = [];
  (servers || []).forEach((server, index) => {
    labels.push(server.name || server.ip || `server-${index + 1}`);
    values.push(1);
  });

  serverChart.data.labels = labels;
  serverChart.data.datasets[0].data = values;
  serverChart.update();
}

async function refreshDashboard() {
  try {
    const status = await fetchStatus();
    const attacks = await fetchAttacks();

    document.getElementById("packetCount").textContent = status.traffic_statistics?.packet_count ?? 0;
    document.getElementById("bandwidth").textContent = status.traffic_statistics?.bandwidth_mbps ?? 0;

    updateTrafficChart(status.traffic_statistics?.bandwidth_mbps || 0);
    updateAttackChart(attacks);
    updateServerChart(status.load_balancer?.servers || []);

    renderList("hostsList", status.connected_hosts || [], (h) => `${h.ip || "unknown"} (${h.mac}) sw:${h.switch} p:${h.in_port}`);
    renderList("blockedList", status.blocked_ip_list || [], (ip) => ip);
    renderList("alertsList", status.alerts || [], (a) => `[${a.severity}] ${a.message}`);
    renderList("switchList", status.switch_statistics || [], (s) => `Switch ${s.dpid}: ${s.packet_count} packets`);
  } catch (error) {
    console.error(error);
  }
}

async function postAction(path, payload) {
  await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
  });
  await refreshDashboard();
}

function bindActions() {
  document.getElementById("enableLbBtn").addEventListener("click", () => postAction("/enable_load_balancer"));
  document.getElementById("disableLbBtn").addEventListener("click", () => postAction("/disable_load_balancer"));
  document.getElementById("blockIpBtn").addEventListener("click", () => {
    const ip = document.getElementById("manualIp").value.trim();
    if (!ip) {
      return;
    }
    postAction("/block_ip", { ip, duration: 120 });
    document.getElementById("manualIp").value = "";
  });
}

createCharts();
bindActions();
refreshDashboard();
setInterval(refreshDashboard, 3000);
