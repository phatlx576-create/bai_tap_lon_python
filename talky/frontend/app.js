const $ = (s) => document.querySelector(s);
const API = window.TAM_API || (["3000", "8000"].includes(location.port) ? `http://${location.hostname}:5000` : location.origin);
let me = null, socket = null, friends = [], groups = [], convos = [], cur = null, msgs = [], more = false;
let typingName = "", typing = false, typingTimer = null, lastTyping = 0, freshId = null, mode = "login";

async function api(url, body) {
  const r = await fetch(API + url, {credentials: "include", ...(body ? {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)} : {})})
    .catch(() => { throw new Error("Không kết nối được máy chủ, hãy kiểm tra backend đã chạy chưa"); });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "Có lỗi xảy ra");
  return d;
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const hue = (s) => [...s].reduce((a, c) => a + c.charCodeAt(0) * 7, 0) % 360;
const hm = (iso) => new Date(iso).toLocaleTimeString("vi-VN", {hour: "2-digit", minute: "2-digit"});
const avatar = (u, size = 40) =>
  `<div class="relative shrink-0" style="width:${size}px;height:${size}px">
    <div class="w-full h-full rounded-full flex items-center justify-center text-white font-medium" style="background:hsl(${hue(u.username)} 55% 42%)">${esc(u.name[0].toUpperCase())}</div>
    ${u.online ? '<span class="absolute -right-0.5 -bottom-0.5 w-3 h-3 rounded-full bg-green-500 border-2 border-white dark:border-slate-900"></span>' : ""}
  </div>`;

function beep() {
  try {
    const a = new AudioContext(), o = a.createOscillator(), g = a.createGain();
    o.connect(g); g.connect(a.destination);
    o.frequency.value = 660; g.gain.value = 0.05;
    o.start(); o.stop(a.currentTime + 0.12);
  } catch (e) {}
}

function setMode(m) {
  mode = m;
  $("#name").classList.toggle("hidden", m !== "register");
  $("#auth-btn").textContent = m === "login" ? "Đăng nhập" : "Tạo tài khoản";
  $("#auth-err").textContent = "";
  for (const k of ["login", "register"]) {
    const t = $("#tab-" + k);
    t.textContent = k === "login" ? "Đăng nhập" : "Đăng ký";
    t.className = "flex-1 py-1.5 rounded-md " + (k === m ? "bg-white dark:bg-slate-700 font-medium" : "text-slate-500");
  }
}
$("#tab-login").onclick = () => setMode("login");
$("#tab-register").onclick = () => setMode("register");
$("#auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    me = await api("/api/" + mode, {username: $("#username").value, password: $("#password").value, name: $("#name").value});
    start();
  } catch (er) { $("#auth-err").textContent = er.message; }
});
$("#logout").onclick = async () => { await api("/api/logout", {}); location.reload(); };
$("#theme").onclick = () => {
  const dark = document.documentElement.classList.toggle("dark");
  localStorage.setItem("talky-theme", dark ? "dark" : "light");
};

function start() {
  $("#auth").classList.add("hidden");
  $("#app").classList.replace("hidden", "flex");
  $("#me").innerHTML = `${avatar({...me, online: true}, 36)}<div class="min-w-0"><p class="truncate text-sm font-medium">${esc(me.name)}</p><p class="truncate text-xs text-slate-500">@${esc(me.username)}</p></div>`;
  $("#emojis").innerHTML = ["😀","😂","🥹","😍","😎","🤔","😭","😡","👍","👏","🙏","🔥","🎉","😴","💯","🤝"]
    .map((e) => `<button type="button" class="w-8 h-8 text-xl rounded hover:bg-slate-100 dark:hover:bg-slate-800">${e}</button>`).join("");
  socket = io(API, {withCredentials: true});
  socket.on("message", onMessage);
  socket.on("refresh", loadFriends);
  socket.on("presence", ({id, online}) => {
    const f = friends.find((x) => x.id === id);
    if (!f) return;
    f.online = online;
    renderFriends();
    if (cur && cur.kind === "u" && cur.id === id) { cur.online = online; updateHeader(); }
  });
  socket.on("typing", ({from, group, name}) => {
    const ok = group ? cur && cur.kind === "g" && cur.id === group : cur && cur.kind === "u" && cur.id === from;
    if (!ok) return;
    typing = true; typingName = name; updateHeader(); renderMsgs(true);
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => { typing = false; updateHeader(); renderMsgs(); }, 2500);
  });
  socket.on("seen", ({by}) => {
    if (!cur || cur.kind !== "u" || cur.id !== by) return;
    msgs.forEach((m) => { if (m.from === me.id) m.seen = true; });
    renderMsgs();
  });
  loadFriends();
}

async function loadFriends() {
  const d = await api("/api/friends");
  friends = d.friends.map((f) => ({...f, kind: "u"}));
  groups = d.groups.map((g) => ({...g, kind: "g", username: "g" + g.id}));
  convos = [...friends, ...groups].sort((a, b) => (b.last ? b.last.id : 0) - (a.last ? a.last.id : 0));
  const total = convos.reduce((n, c) => n + c.unread, 0);
  document.title = total ? `(${total}) Talky` : "Talky";
  $("#reqs").innerHTML = d.requests.length
    ? '<p class="px-4 pt-3 text-xs text-slate-500">Lời mời kết bạn</p>' + d.requests.map((r) =>
      `<div class="flex items-center gap-2 px-4 py-2">${avatar(r, 32)}<span class="flex-1 truncate text-sm">${esc(r.name)}</span>
       <button data-ok="${r.id}" class="text-xs px-2.5 py-1 rounded-md bg-brand text-white">Chấp nhận</button>
       <button data-no="${r.id}" class="text-xs px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800">Từ chối</button></div>`).join("")
    : "";
  if (cur) {
    const c = convos.find((x) => x.kind === cur.kind && x.id === cur.id);
    if (c) { cur = c; updateHeader(); }
  }
  renderFriends();
}

function renderFriends() {
  $("#list").innerHTML = convos.length ? convos.map((c) => {
    const l = c.last, un = c.unread > 0;
    const who = l ? (l.from === me.id ? "Bạn: " : c.kind === "g" ? l.sender + ": " : "") : "";
    const body = l ? (l.img && !l.text ? "[Ảnh]" : l.text) : c.kind === "g" ? "Nhóm mới tạo" : "Hãy gửi lời chào";
    const active = cur && cur.kind === c.kind && cur.id === c.id;
    return `<div data-k="${c.kind}" data-id="${c.id}" class="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800 ${active ? "bg-slate-100 dark:bg-slate-800" : ""}">
      ${avatar(c, 44)}
      <div class="min-w-0 flex-1">
        <div class="flex justify-between gap-2"><span class="truncate ${un ? "font-medium" : ""}">${esc(c.name)}</span><span class="text-xs text-slate-400">${l ? hm(l.at) : ""}</span></div>
        <div class="flex justify-between gap-2 text-sm ${un ? "font-medium" : "text-slate-500"}">
          <span class="truncate">${esc(who + body)}</span>
          ${un ? `<span class="bg-brand text-white text-xs rounded-full px-1.5">${c.unread}</span>` : ""}
        </div>
      </div></div>`;
  }).join("") : '<p class="px-4 py-6 text-sm text-slate-400 text-center">Chưa có cuộc trò chuyện nào. Hãy kết bạn hoặc tạo nhóm.</p>';
}

$("#list").addEventListener("click", (e) => {
  const el = e.target.closest("[data-id]");
  if (el) openChat(el.dataset.k, +el.dataset.id);
});
$("#reqs").addEventListener("click", async (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  try { await api("/api/friends/respond", {id: +(b.dataset.ok || b.dataset.no), accept: !!b.dataset.ok}); }
  catch (er) { alert(er.message); }
});

let searchTimer;
$("#search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(doSearch, 300); });
async function doSearch() {
  const q = $("#search").value.trim(), box = $("#results");
  if (q.length < 2) { box.classList.add("hidden"); return; }
  const rs = await api("/api/search?q=" + encodeURIComponent(q));
  const label = {friend: "Bạn bè", sent: "Đã gửi lời mời", received: "Đang chờ bạn chấp nhận"};
  box.innerHTML = rs.length ? rs.map((u) =>
    `<div class="flex items-center gap-2 px-3 py-2">${avatar(u, 32)}
      <div class="min-w-0 flex-1"><p class="truncate text-sm">${esc(u.name)}</p><p class="truncate text-xs text-slate-500">@${esc(u.username)}</p></div>
      ${u.status === "none" ? `<button data-add="${esc(u.username)}" class="text-xs px-2.5 py-1 rounded-md bg-brand text-white">Kết bạn</button>` : `<span class="text-xs text-slate-400">${label[u.status]}</span>`}
    </div>`).join("") : '<p class="p-3 text-sm text-slate-400">Không tìm thấy ai khớp với từ khóa.</p>';
  box.classList.remove("hidden");
}
$("#results").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-add]");
  if (!b) return;
  try { await api("/api/friends/request", {username: b.dataset.add}); doSearch(); }
  catch (er) { alert(er.message); }
});

const target = () => (cur.kind === "g" ? {group: cur.id} : {to: cur.id});

function updateHeader() {
  if (!cur) return;
  const sub = typing ? `<span class="text-brand">${cur.kind === "g" ? esc(typingName) + " " : ""}đang nhập…</span>`
    : cur.kind === "g" ? `${cur.members.length} thành viên` : cur.online ? "Đang hoạt động" : "Ngoại tuyến";
  $("#head").innerHTML = `${avatar(cur, 40)}<div><p class="font-medium leading-tight">${esc(cur.name)}</p><p class="text-xs text-slate-500">${sub}</p></div>`;
}

async function openChat(kind, id) {
  const c = convos.find((x) => x.kind === kind && x.id === id);
  if (!c) return;
  cur = c; typing = false; msgs = [];
  $("#app").classList.add("open");
  $("#empty").classList.add("hidden");
  $("#panel").classList.replace("hidden", "flex");
  updateHeader(); renderFriends(); $("#text").focus();
  try {
    const d = await api(`/api/messages/${kind}/${id}`);
    if (!cur || cur.kind !== kind || cur.id !== id) return;
    msgs = d.messages; more = d.more;
    renderMsgs(true);
    socket.emit("seen", kind === "g" ? {group: id} : {from: id});
  } catch (er) { alert(er.message); }
}
$("#back").onclick = () => $("#app").classList.remove("open");

const SCROLL = "const b=document.getElementById('msgs');if(b.scrollHeight-b.scrollTop-b.clientHeight<600)b.scrollTop=b.scrollHeight";

function renderMsgs(bottom = false) {
  const box = $("#msgs"), offset = box.scrollHeight - box.scrollTop;
  const lastMine = [...msgs].reverse().find((m) => m.from === me.id);
  let html = more ? '<button id="more" class="block mx-auto text-xs text-brand py-1">Tải tin nhắn cũ hơn</button>' : "";
  msgs.forEach((m, i) => {
    const mine = m.from === me.id, p = msgs[i - 1];
    const gap = !p || new Date(m.at) - new Date(p.at) > 300000;
    if (gap) html += `<div class="text-center text-xs text-slate-400 my-3">${new Date(m.at).toLocaleString("vi-VN", {hour: "2-digit", minute: "2-digit", day: "2-digit", month: "2-digit"})}</div>`;
    const same = p && !gap && p.from === m.from;
    const label = cur.kind === "g" && !mine && !same;
    if (label) html += `<p class="text-xs text-slate-500 ml-1 mt-2">${esc(m.sender)}</p>`;
    const img = m.img ? `<a href="${esc(API + m.img)}" target="_blank"><img src="${esc(API + m.img)}" alt="Ảnh" class="rounded-xl max-h-64" onload="${SCROLL}"></a>` : "";
    const txt = m.text ? `<div class="${m.img ? "px-2.5 py-1" : ""}">${esc(m.text)}</div>` : "";
    html += `<div class="flex ${mine ? "justify-end" : "justify-start"} ${same || label ? "mt-0.5" : "mt-2"}">` +
      `<div class="${m.id === freshId ? "pop" : ""} max-w-[75%] ${m.img ? "p-1" : "px-3.5 py-2"} rounded-2xl break-words whitespace-pre-wrap ${mine ? "bg-brand text-white" : "bg-slate-100 dark:bg-slate-800"}" title="${hm(m.at)}">${img}${txt}</div></div>`;
    if (m === lastMine && cur.kind === "u") html += `<div class="text-right text-[11px] text-slate-400 mt-0.5">${m.seen ? "Đã xem" : "Đã gửi"}</div>`;
  });
  if (typing) html += '<div class="flex mt-2"><div class="dots flex gap-1 bg-slate-100 dark:bg-slate-800 rounded-2xl px-4 py-3"><i></i><i></i><i></i></div></div>';
  if (!msgs.length) html += '<p class="text-center text-sm text-slate-400 mt-10">Chưa có tin nhắn nào. Hãy gửi lời chào đầu tiên.</p>';
  box.innerHTML = html;
  box.scrollTop = bottom ? box.scrollHeight : box.scrollHeight - offset;
}

$("#msgs").addEventListener("click", async (e) => {
  if (e.target.id !== "more" || !msgs.length) return;
  try {
    const d = await api(`/api/messages/${cur.kind}/${cur.id}?before=${msgs[0].id}`);
    msgs = d.messages.concat(msgs); more = d.more; renderMsgs();
  } catch (er) { alert(er.message); }
});

function onMessage(m) {
  const kind = m.group ? "g" : "u", id = m.group || (m.from === me.id ? m.to : m.from);
  if (cur && cur.kind === kind && cur.id === id) {
    msgs.push(m); freshId = m.id; typing = false; updateHeader(); renderMsgs(true);
    if (m.from !== me.id) socket.emit("seen", kind === "g" ? {group: id} : {from: id});
  } else if (m.from !== me.id) beep();
  loadFriends();
}

function send() {
  const t = $("#text").value.trim();
  if (!t || !cur) return;
  socket.emit("send", {...target(), text: t});
  $("#text").value = "";
}
$("#send").onclick = send;
$("#text").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.isComposing) send(); });
$("#text").addEventListener("input", () => {
  if (cur && Date.now() - lastTyping > 1500) { lastTyping = Date.now(); socket.emit("typing", target()); }
});
$("#emoji-btn").onclick = () => $("#emojis").classList.toggle("hidden");
$("#emojis").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  $("#text").value += b.textContent;
  $("#emojis").classList.add("hidden");
  $("#text").focus();
});

$("#img-btn").onclick = () => $("#file").click();
$("#file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file || !cur) return;
  const fd = new FormData();
  fd.append("file", file);
  try {
    const r = await fetch(API + "/api/upload", {method: "POST", body: fd, credentials: "include"});
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || "Không gửi được ảnh");
    socket.emit("send", {...target(), img: d.url, text: ""});
  } catch (er) { alert(er.message); }
});

$("#new-group").onclick = () => {
  $("#gname").value = ""; $("#gerr").textContent = "";
  $("#gfriends").innerHTML = friends.length ? friends.map((f) =>
    `<label class="flex items-center gap-2 p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800"><input type="checkbox" value="${f.id}">${avatar(f, 28)}<span class="truncate">${esc(f.name)}</span></label>`).join("")
    : '<p class="text-sm text-slate-400">Bạn cần kết bạn trước khi tạo nhóm.</p>';
  $("#gdlg").showModal();
};
$("#gcancel").onclick = () => $("#gdlg").close();
$("#gform").addEventListener("submit", async (e) => {
  e.preventDefault();
  const members = [...document.querySelectorAll("#gfriends input:checked")].map((i) => +i.value);
  try {
    const d = await api("/api/groups", {name: $("#gname").value, members});
    $("#gdlg").close();
    await loadFriends();
    openChat("g", d.id);
  } catch (er) { $("#gerr").textContent = er.message; }
});

setMode("login");
api("/api/me").then((u) => { me = u; start(); }).catch(() => {});
