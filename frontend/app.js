"use strict";

/* =====================================================================
 *  SecureChat - logic phía trình duyệt
 *
 *  Chat 1-1 (mã hóa đầu cuối):
 *    ECDH P-256 (khóa bí mật chỉ nằm ở trình duyệt) -> HKDF-SHA256 -> AES-256-GCM.
 *
 *  Chat nhóm:
 *    Người tạo nhóm sinh 1 khóa AES-256 ngẫu nhiên, rồi "gói" (mã hóa) khóa đó riêng
 *    cho từng thành viên bằng khóa chung ECDH 1-1 của họ. Server chỉ lưu khóa đã gói
 *    và bản mã, không bao giờ thấy khóa nhóm hay nội dung.
 *
 *  Ảnh/tệp: mã hóa AES-GCM ngay trên trình duyệt; tên tệp, loại, kích thước cũng
 *  được mã hóa riêng. Tìm kiếm chạy ở trình duyệt sau khi giải mã.
 * ===================================================================== */

const API = "/api";
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const HISTORY_LIMIT = 50;
const POLL_MS = 10000;
const MAX_FILE_BYTES = 4 * 1024 * 1024;          // 4 MB
const SEARCH_CAP = 1000;                          // tối đa số tin nhắn quét khi tìm kiếm
const IMAGE_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"];

const TOKEN_KEY = "sc_token";
const USER_KEY = "sc_user";
const privStorageKey = (username) => `sc_priv_${username}`;

const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);

const state = {
  mode: "login",          // "login" | "register"
  token: null,
  me: null,               // {id, username, public_key}
  privateKey: null,       // CryptoKey (ECDH)
  socket: null,
  friends: [],
  groups: [],
  online: new Set(),
  unread: {},             // "dm:5" / "group:2" -> số tin chưa đọc
  current: null,          // {type: "dm" | "group", id}
  aesKeys: new Map(),     // friendId -> CryptoKey (khóa chung 1-1)
  groupRaw: new Map(),    // groupId -> Uint8Array (khóa nhóm, dùng để gói cho thành viên mới)
  groupKeys: new Map(),   // groupId -> CryptoKey (AES-GCM)
  oldestId: null,
  chatLoadId: 0,          // chống lẫn dữ liệu khi đổi cuộc chat nhanh
};

let pollTimer = null;
let searchTimer = null;
let toastTimer = null;
let typingTimer = null;
let lastTypingSent = 0;
let searchSeq = 0;
let lazyObserver = null;

/* ============================ Tiện ích ============================ */

function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;   // textContent => chống XSS
  return e;
}

function toast(message) {
  const t = $("toast");
  t.textContent = message;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 3000);
}

function initial(name) {
  return (name || "?").charAt(0).toUpperCase();
}

function formatTime(sqlDate) {
  // SQLite lưu UTC dạng "YYYY-MM-DD HH:MM:SS"
  const d = new Date(String(sqlDate).replace(" ", "T") + "Z");
  if (isNaN(d)) return "";
  const time = d.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === new Date().toDateString()
    ? time
    : `${time} ${d.toLocaleDateString("vi-VN")}`;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

const b64 = {
  encode(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(s);
  },
  decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

/** Tách văn bản thành các đoạn chữ và đường dẫn http/https (hàm thuần, dễ kiểm thử). */
function splitLinks(text) {
  const parts = [];
  const re = /https?:\/\/[^\s<>"']+/gi;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    let url = m[0];
    let trail = "";
    const t = url.match(/[.,!?;:)\]]+$/);       // bỏ dấu câu dính ở cuối đường dẫn
    if (t) { trail = t[0]; url = url.slice(0, -trail.length); }

    let valid = true;
    try { new URL(url); } catch { valid = false; }

    if (m.index > last) parts.push({ type: "text", text: text.slice(last, m.index) });
    parts.push(valid ? { type: "link", text: url } : { type: "text", text: url });
    if (trail) parts.push({ type: "text", text: trail });
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push({ type: "text", text: text.slice(last) });
  return parts;
}

function appendLinkified(node, text) {
  for (const p of splitLinks(text)) {
    if (p.type === "link") {
      const a = el("a", null, p.text);
      a.href = p.text;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      node.appendChild(a);
    } else {
      node.appendChild(document.createTextNode(p.text));
    }
  }
}

/* ============================ Mật mã ============================ */

const cleanPublic = (j) => ({ kty: "EC", crv: "P-256", x: j.x, y: j.y });
const cleanPrivate = (j) => ({ kty: "EC", crv: "P-256", x: j.x, y: j.y, d: j.d });

async function generateKeyPair() {
  const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return { publicJwk: cleanPublic(pub), privateJwk: cleanPrivate(priv) };
}

function importPrivateKey(jwk) {
  return crypto.subtle.importKey("jwk", cleanPrivate(jwk), ECDH, false, ["deriveBits"]);
}

/** ECDH -> HKDF -> khóa AES-256-GCM dùng chung giữa 2 người. */
async function deriveAesKey(myPrivateKey, theirPublicJwkString) {
  const theirPublic = await crypto.subtle.importKey(
    "jwk", cleanPublic(JSON.parse(theirPublicJwkString)), ECDH, true, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: theirPublic }, myPrivateKey, 256
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode("SecureChat-salt-v1"),
      info: enc.encode("SecureChat-aes-key"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Mã hóa mảng byte bằng AES-GCM. aadStr gắn vào bản mã để chống giả mạo/đảo chiều. */
async function encryptBytes(key, bytes, aadStr) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(aadStr) }, key, bytes
  );
  return { ciphertext: b64.encode(ct), iv: b64.encode(iv) };
}

async function decryptBytes(key, ciphertext, iv, aadStr) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64.decode(iv), additionalData: enc.encode(aadStr) },
    key,
    b64.decode(ciphertext)
  );
  return new Uint8Array(plain);
}

// AAD của tin nhắn: 1-1 gắn người gửi + người nhận; nhóm gắn id nhóm + người gửi.
const msgAad = (type, msg) =>
  type === "dm" ? `${msg.sender_id}:${msg.receiver_id}` : `g:${msg.group_id}:${msg.sender_id}`;
const outAad = (conv) =>
  conv.type === "dm" ? `${state.me.id}:${conv.id}` : `g:${conv.id}:${state.me.id}`;
// AAD khi gói khóa nhóm cho 1 thành viên
const wrapAad = (wrapperId, memberId) => `gkey:${wrapperId}:${memberId}`;

/** Mã xác minh khóa: hai bên so sánh để chắc chắn không bị tấn công xen giữa. */
async function fingerprint(pubA, pubB) {
  const canon = [pubA, pubB]
    .map((s) => { const k = JSON.parse(s); return `${k.x}.${k.y}`; })
    .sort()
    .join("|");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canon)));
  const hex = Array.from(hash.slice(0, 8)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g).join(" ");
}

async function getAesKey(friend) {
  if (!state.aesKeys.has(friend.id)) {
    state.aesKeys.set(friend.id, await deriveAesKey(state.privateKey, friend.public_key));
  }
  return state.aesKeys.get(friend.id);
}

/** Mở khóa nhóm: giải mã khóa nhóm đã được người tạo gói riêng cho mình. */
async function getGroupRaw(group) {
  if (!state.groupRaw.has(group.id)) {
    const mk = group.my_key;
    const wrapKey = await deriveAesKey(state.privateKey, mk.wrapper_public_key);
    const raw = await decryptBytes(wrapKey, mk.ciphertext, mk.iv, wrapAad(mk.wrapper_id, state.me.id));
    state.groupRaw.set(group.id, raw);
  }
  return state.groupRaw.get(group.id);
}

async function getGroupKey(group) {
  if (!state.groupKeys.has(group.id)) {
    const raw = await getGroupRaw(group);
    state.groupKeys.set(
      group.id,
      await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
    );
  }
  return state.groupKeys.get(group.id);
}

/* ============================ Cuộc trò chuyện ============================ */

const convKey = (c) => `${c.type}:${c.id}`;
const scopeOf = (c) => (c.type === "dm" ? "dm" : "group");

function convRef(c) {
  return c.type === "dm"
    ? state.friends.find((f) => f.id === c.id)
    : state.groups.find((g) => g.id === c.id);
}

function isCurrent(type, id) {
  return !!state.current && state.current.type === type && state.current.id === id;
}

async function getConvKey(conv) {
  const ref = convRef(conv);
  if (!ref) throw new Error("Không tìm thấy cuộc trò chuyện");
  return conv.type === "dm" ? getAesKey(ref) : getGroupKey(ref);
}

function senderName(conv, senderId) {
  if (senderId === state.me.id) return "Bạn";
  const ref = convRef(conv);
  if (!ref) return "Ẩn danh";
  if (conv.type === "dm") return ref.username;
  const m = ref.members.find((x) => x.id === senderId);
  return m ? m.username : "Thành viên cũ";
}

/** Mã hóa và gửi 1 tin (chữ / tệp / thông báo hệ thống). Trả về tin nhắn server đã lưu. */
async function sendPayload(conv, kind, bytes, meta) {
  const key = await getConvKey(conv);
  const body = await encryptBytes(key, bytes, outAad(conv));
  const payload = { kind, ciphertext: body.ciphertext, iv: body.iv };

  if (meta) {
    const m = await encryptBytes(key, enc.encode(JSON.stringify(meta)), outAad(conv) + ":meta");
    payload.meta = JSON.stringify({ ct: m.ciphertext, iv: m.iv });
  }

  let event;
  if (conv.type === "dm") {
    payload.to = conv.id;
    event = "send_message";
  } else {
    payload.group_id = conv.id;
    event = "send_group_message";
  }

  const res = await emitAck(event, payload, kind === "file" ? 120000 : 10000);
  if (!res.ok) throw new Error(res.error || "Gửi thất bại");
  return res.message;
}

async function sendText(conv, text) {
  const msg = await sendPayload(conv, "text", enc.encode(text));
  if (isCurrent(conv.type, conv.id)) {
    appendMessage(conv, msg, { ok: true, kind: "text", text });
    scrollToBottom();
    renderSeen();
  }
}

async function sendSystem(conv, text) {
  try {
    const msg = await sendPayload(conv, "system", enc.encode(text));
    if (isCurrent(conv.type, conv.id)) {
      appendMessage(conv, msg, { ok: true, kind: "system", text });
      scrollToBottom();
    }
  } catch { /* thông báo hệ thống không quan trọng, bỏ qua lỗi */ }
}

async function sendFile(conv, file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const meta = { name: file.name, type: file.type || "application/octet-stream", size: file.size };
  const msg = await sendPayload(conv, "file", bytes, meta);
  if (isCurrent(conv.type, conv.id)) {
    appendMessage(conv, msg, { ok: true, kind: "file", meta, localBlob: file });
    scrollToBottom();
    renderSeen();
  }
}

/** Giải mã 1 tin. Với tệp chỉ giải mã phần thông tin (tên/loại/kích thước), nội dung tải sau. */
async function decryptMessage(conv, msg) {
  if (msg.deleted) return { ok: true, kind: msg.kind, deleted: true };
  try {
    const key = await getConvKey(conv);
    const aad = msgAad(conv.type, msg);
    if (msg.kind === "file") {
      const m = JSON.parse(msg.meta);
      const raw = JSON.parse(dec.decode(await decryptBytes(key, m.ct, m.iv, aad + ":meta")));
      const meta = {
        name: String(raw.name || "tệp").slice(0, 200),
        type: String(raw.type || "application/octet-stream"),
        size: Number(raw.size) || 0,
      };
      return { ok: true, kind: "file", meta };
    }
    const text = dec.decode(await decryptBytes(key, msg.ciphertext, msg.iv, aad));
    return { ok: true, kind: msg.kind, text };
  } catch {
    return { ok: false, kind: msg.kind };
  }
}

async function fetchFileBlob(conv, msg, meta) {
  const r = await emitAck("get_blob", { scope: scopeOf(conv), id: msg.id }, 60000);
  if (!r.ok) throw new Error(r.error || "Không tải được tệp");
  const key = await getConvKey(conv);
  const bytes = await decryptBytes(key, r.ciphertext, r.iv, msgAad(conv.type, msg));
  return new Blob([bytes], { type: meta.type });
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

/* ============================ Gọi API / socket ============================ */

async function api(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth && state.token) headers.Authorization = `Bearer ${state.token}`;

  let res;
  try {
    res = await fetch(API + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error("Không kết nối được tới server");
  }

  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && auth) {
    logout();
    throw new Error("Phiên đăng nhập đã hết hạn");
  }
  if (!res.ok) throw new Error(data.error || "Có lỗi xảy ra");
  return data;
}

function emitAck(event, data, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    if (!state.socket || !state.socket.connected) {
      return reject(new Error("Mất kết nối tới server"));
    }
    const timer = setTimeout(() => reject(new Error("Server phản hồi quá lâu")), timeoutMs);
    state.socket.emit(event, data, (res) => {
      clearTimeout(timer);
      resolve(res || {});
    });
  });
}

/* ============================ Đăng nhập / Đăng ký ============================ */

function showAuth(message) {
  $("chat-screen").classList.add("hidden");
  $("auth-screen").classList.remove("hidden");
  if (message) showAuthError(message);
}

function showChat() {
  $("auth-screen").classList.add("hidden");
  $("chat-screen").classList.remove("hidden");
}

function showAuthError(message) {
  const box = $("auth-error");
  box.textContent = message;
  box.classList.remove("hidden");
}

function setMode(mode) {
  state.mode = mode;
  $("tab-login").classList.toggle("active", mode === "login");
  $("tab-register").classList.toggle("active", mode === "register");
  $("auth-submit").textContent = mode === "login" ? "Đăng nhập" : "Tạo tài khoản";
  $("auth-error").classList.add("hidden");

  // Ô nhập lại mật khẩu chỉ hiện khi đăng ký
  const isRegister = mode === "register";
  $("confirm-wrap").classList.toggle("hidden", !isRegister);
  $("auth-confirm").required = isRegister;
  $("auth-confirm").value = "";
}

function clearSession() {
  // Chỉ xóa token. KHÔNG xóa khóa bí mật, nếu không sẽ không đọc được tin cũ.
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

async function onAuthSubmit(e) {
  e.preventDefault();
  $("auth-error").classList.add("hidden");
  const username = $("auth-username").value.trim();
  const password = $("auth-password").value;
  const btn = $("auth-submit");

  if (state.mode === "register" && password !== $("auth-confirm").value) {
    showAuthError("Mật khẩu nhập lại không khớp");
    return;
  }
  btn.disabled = true;

  try {
    let data;
    if (state.mode === "register") {
      const keys = await generateKeyPair();
      data = await api("/auth/register", {
        method: "POST",
        auth: false,
        body: { username, password, public_key: JSON.stringify(keys.publicJwk) },
      });
      // Chỉ lưu khóa bí mật sau khi server đã nhận đăng ký thành công
      localStorage.setItem(privStorageKey(data.user.username), JSON.stringify(keys.privateJwk));
    } else {
      data = await api("/auth/login", { method: "POST", auth: false, body: { username, password } });
    }

    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    await startApp(data.token, data.user);
    $("auth-password").value = "";
    $("auth-confirm").value = "";
  } catch (err) {
    logout();                    // dọn socket/trạng thái nếu startApp lỗi giữa chừng
    showAuthError(err.message);
  } finally {
    btn.disabled = false;
  }
}

async function startApp(token, user) {
  const privStr = localStorage.getItem(privStorageKey(user.username));
  if (!privStr) {
    throw new Error(
      "Trình duyệt này không có khóa bí mật của tài khoản. Hãy đăng nhập bằng trình duyệt đã dùng để đăng ký."
    );
  }
  const privJwk = JSON.parse(privStr);
  const pubJwk = JSON.parse(user.public_key);
  if (privJwk.x !== pubJwk.x || privJwk.y !== pubJwk.y) {
    throw new Error("Khóa bí mật trên thiết bị không khớp với tài khoản này.");
  }

  state.privateKey = await importPrivateKey(privJwk);
  state.token = token;
  state.me = user;
  state.aesKeys.clear();
  state.groupRaw.clear();
  state.groupKeys.clear();
  state.unread = {};
  state.current = null;

  $("me-name").textContent = user.username;
  $("me-avatar").textContent = initial(user.username);
  showChat();
  showEmptyChat();

  connectSocket();
  await refreshSocial();
  clearInterval(pollTimer);
  pollTimer = setInterval(() => refreshSocial().catch(() => {}), POLL_MS);
}

function logout() {
  clearInterval(pollTimer);
  if (state.socket) state.socket.disconnect();
  state.socket = null;
  state.token = null;
  state.me = null;
  state.privateKey = null;
  state.friends = [];
  state.groups = [];
  state.online = new Set();
  state.current = null;
  state.aesKeys.clear();
  state.groupRaw.clear();
  state.groupKeys.clear();
  clearSession();
  $("friends-list").replaceChildren();
  $("groups-list").replaceChildren();
  $("search-results").replaceChildren();
  $("search-input").value = "";
  closeModal("group-modal");
  closeModal("group-info-modal");
  showAuth();
}

/* ============================ Socket.IO ============================ */

function connectSocket() {
  if (state.socket) state.socket.disconnect();
  const socket = io({ auth: { token: state.token } });
  state.socket = socket;

  socket.on("connect_error", () => toast("Mất kết nối tới server"));

  socket.on("online_list", (ids) => {
    state.online = new Set(ids);
    renderFriends();
    updateChatStatus();
  });
  socket.on("user_online", ({ user_id }) => {
    state.online.add(user_id);
    renderFriends();
    updateChatStatus();
  });
  socket.on("user_offline", ({ user_id }) => {
    state.online.delete(user_id);
    renderFriends();
    updateChatStatus();
  });

  socket.on("new_message", (msg) => handleIncoming("dm", msg));
  socket.on("new_group_message", (msg) => handleIncoming("group", msg));

  socket.on("typing", ({ user_id }) => {
    if (isCurrent("dm", user_id)) showTyping();
  });

  socket.on("messages_read", ({ by }) => {
    if (!isCurrent("dm", by)) return;
    $("messages").querySelectorAll(".msg.me").forEach((m) => (m.dataset.read = "1"));
    renderSeen();
  });

  socket.on("message_recalled", ({ scope, id, conv_id }) => {
    const type = scope === "dm" ? "dm" : "group";
    if (isCurrent(type, conv_id)) markRecalled(id);
  });

  socket.on("groups_changed", async () => {
    try { await loadGroups(); } catch { /* bỏ qua */ }
    refreshGroupModals();
  });
}

async function handleIncoming(type, msg) {
  const mine = msg.sender_id === state.me.id;
  let conv;

  if (type === "dm") {
    const fid = mine ? msg.receiver_id : msg.sender_id;
    if (!state.friends.find((f) => f.id === fid)) await loadFriends();
    if (!state.friends.find((f) => f.id === fid)) return;
    conv = { type: "dm", id: fid };
  } else {
    if (!state.groups.find((g) => g.id === msg.group_id)) await loadGroups();
    if (!state.groups.find((g) => g.id === msg.group_id)) return;
    conv = { type: "group", id: msg.group_id };
  }

  if (isCurrent(conv.type, conv.id)) {
    const res = await decryptMessage(conv, msg);
    appendMessage(conv, msg, res);
    scrollToBottom();
    if (type === "dm" && !mine) {
      updateChatStatus();        // tắt chữ "đang nhập..." khi tin đã tới
      markRead(conv.id);
    }
  } else if (!mine && msg.kind !== "system") {
    const k = convKey(conv);
    state.unread[k] = (state.unread[k] || 0) + 1;
    renderFriends();
    renderGroups();
  }
}

/* ============================ Bạn bè & lời mời ============================ */

async function refreshSocial() {
  await Promise.all([loadFriends(), loadRequests(), loadGroups()]);
}

async function loadFriends() {
  state.friends = await api("/friends");
  renderFriends();
}

function renderFriends() {
  const box = $("friends-list");
  box.replaceChildren();

  if (state.friends.length === 0) {
    box.appendChild(el("div", "empty-hint", "Chưa có bạn bè. Hãy tìm và kết bạn ở ô phía trên."));
    return;
  }

  for (const f of state.friends) {
    const active = isCurrent("dm", f.id);
    const row = el("div", "friend-item" + (active ? " active" : ""));
    row.appendChild(el("div", "avatar", initial(f.username)));
    row.appendChild(el("span", "friend-name", f.username));

    const unread = state.unread[`dm:${f.id}`] || 0;
    if (unread > 0) row.appendChild(el("span", "unread", String(unread)));

    row.appendChild(el("span", "status-dot" + (state.online.has(f.id) ? " online" : "")));
    row.addEventListener("click", () => openChat("dm", f.id));
    box.appendChild(row);
  }
}

async function loadRequests() {
  const list = await api("/friends/requests");
  const section = $("requests-section");
  const box = $("requests-list");
  box.replaceChildren();

  section.classList.toggle("hidden", list.length === 0);
  $("requests-count").textContent = String(list.length);

  for (const r of list) {
    const row = el("div", "request-item");
    row.appendChild(el("div", "avatar", initial(r.username)));
    row.appendChild(el("span", "result-name", r.username));

    const actions = el("div", "result-actions");
    const accept = el("button", "btn btn-small btn-primary", "Chấp nhận");
    const decline = el("button", "btn btn-small btn-ghost", "Từ chối");
    accept.addEventListener("click", () => answerRequest(r.request_id, "accept"));
    decline.addEventListener("click", () => answerRequest(r.request_id, "decline"));
    actions.append(accept, decline);

    row.appendChild(actions);
    box.appendChild(row);
  }
}

async function answerRequest(requestId, action) {
  try {
    const data = await api(`/friends/${requestId}/${action}`, { method: "POST" });
    toast(data.message);
    await refreshSocial();
  } catch (err) {
    toast(err.message);
  }
}

/* ============================ Tìm kiếm người dùng ============================ */

async function runSearch() {
  const q = $("search-input").value.trim();
  const box = $("search-results");
  if (!q) {
    box.replaceChildren();
    return;
  }
  try {
    const results = await api(`/users/search?q=${encodeURIComponent(q)}`);
    renderSearch(results);
  } catch (err) {
    toast(err.message);
  }
}

function renderSearch(results) {
  const box = $("search-results");
  box.replaceChildren();

  if (results.length === 0) {
    box.appendChild(el("div", "empty-hint", "Không tìm thấy người dùng nào."));
    return;
  }

  for (const u of results) {
    const row = el("div", "result-item");
    row.appendChild(el("div", "avatar", initial(u.username)));
    row.appendChild(el("span", "result-name", u.username));

    const actions = el("div", "result-actions");
    if (u.relation === "none") {
      const b = el("button", "btn btn-small btn-primary", "Kết bạn");
      b.addEventListener("click", () => sendFriendRequest(u.id));
      actions.appendChild(b);
    } else if (u.relation === "pending_received") {
      // Gửi lại lời mời cho người đã mời mình => server tự chấp nhận
      const b = el("button", "btn btn-small btn-primary", "Chấp nhận");
      b.addEventListener("click", () => sendFriendRequest(u.id));
      actions.appendChild(b);
    } else if (u.relation === "pending_sent") {
      actions.appendChild(el("span", "relation-text", "Đã gửi lời mời"));
    } else {
      actions.appendChild(el("span", "relation-text", "Bạn bè"));
    }

    row.appendChild(actions);
    box.appendChild(row);
  }
}

async function sendFriendRequest(userId) {
  try {
    const data = await api("/friends/request", { method: "POST", body: { user_id: userId } });
    toast(data.message);
    await Promise.all([runSearch(), refreshSocial()]);
  } catch (err) {
    toast(err.message);
  }
}

/* ============================ Nhóm ============================ */

async function loadGroups() {
  state.groups = await api("/groups");
  renderGroups();

  // Nếu đang mở nhóm mà mình không còn ở trong đó (bị xóa/rời/nhóm bị xóa)
  if (state.current && state.current.type === "group" && !convRef(state.current)) {
    closeChat();
    toast("Bạn không còn ở trong nhóm này");
  }
}

function renderGroups() {
  const box = $("groups-list");
  box.replaceChildren();

  if (state.groups.length === 0) {
    box.appendChild(el("div", "empty-hint", "Chưa có nhóm nào."));
    return;
  }

  for (const g of state.groups) {
    const row = el("div", "friend-item" + (isCurrent("group", g.id) ? " active" : ""));
    row.appendChild(el("div", "avatar group-avatar", "👥"));
    row.appendChild(el("span", "friend-name", g.name));

    const unread = state.unread[`group:${g.id}`] || 0;
    if (unread > 0) row.appendChild(el("span", "unread", String(unread)));

    row.addEventListener("click", () => openChat("group", g.id));
    box.appendChild(row);
  }
}

function openModal(id) { $(id).classList.remove("hidden"); }
function closeModal(id) { $(id).classList.add("hidden"); }

function openGroupModal() {
  $("group-name").value = "";
  $("group-modal-error").classList.add("hidden");

  const list = $("group-friend-list");
  list.replaceChildren();
  if (state.friends.length === 0) {
    list.appendChild(el("div", "empty-hint", "Bạn cần có bạn bè để tạo nhóm."));
  }
  for (const f of state.friends) {
    const row = el("label", "check-row");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = String(f.id);
    row.append(cb, el("span", "grow", f.username));
    list.appendChild(row);
  }
  openModal("group-modal");
  $("group-name").focus();
}

async function createGroup() {
  const err = $("group-modal-error");
  err.classList.add("hidden");
  const name = $("group-name").value.trim();
  const ids = Array.from($("group-friend-list").querySelectorAll("input:checked")).map((i) => Number(i.value));

  if (!name) { err.textContent = "Hãy đặt tên nhóm"; err.classList.remove("hidden"); return; }
  if (ids.length < 1) { err.textContent = "Hãy chọn ít nhất 1 người bạn"; err.classList.remove("hidden"); return; }

  const btn = $("group-create-btn");
  btn.disabled = true;
  try {
    // 1. Sinh khóa nhóm ngẫu nhiên (chỉ tồn tại ở trình duyệt)
    const raw = crypto.getRandomValues(new Uint8Array(32));

    // 2. Gói khóa riêng cho từng thành viên bằng khóa chung ECDH 1-1 của họ (và cả mình)
    const members = [];
    const selfKey = await deriveAesKey(state.privateKey, state.me.public_key);
    members.push({ user_id: state.me.id, ...(await encryptBytes(selfKey, raw, wrapAad(state.me.id, state.me.id))) });
    for (const fid of ids) {
      const friend = state.friends.find((f) => f.id === fid);
      const key = await getAesKey(friend);
      members.push({ user_id: fid, ...(await encryptBytes(key, raw, wrapAad(state.me.id, fid))) });
    }

    const group = await api("/groups", { method: "POST", body: { name, members } });
    state.groupRaw.set(group.id, raw);
    await loadGroups();
    closeModal("group-modal");
    await openChat("group", group.id);
    sendSystem({ type: "group", id: group.id }, `${state.me.username} đã tạo nhóm "${name}"`);
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove("hidden");
  } finally {
    btn.disabled = false;
  }
}

function openGroupInfo() {
  if (!state.current || state.current.type !== "group") return;
  renderGroupInfo();
  openModal("group-info-modal");
}

function refreshGroupModals() {
  if (!$("group-info-modal").classList.contains("hidden")) {
    if (state.current && state.current.type === "group" && convRef(state.current)) renderGroupInfo();
    else closeModal("group-info-modal");
  }
  if (state.current && state.current.type === "group") updateChatStatus();
}

function renderGroupInfo() {
  const group = convRef(state.current);
  if (!group) return;
  const isOwner = group.owner_id === state.me.id;

  $("group-info-title").textContent = group.name;

  const list = $("group-members");
  list.replaceChildren();
  for (const m of group.members) {
    const row = el("div", "check-row");
    row.appendChild(el("span", "grow", m.id === state.me.id ? `${m.username} (bạn)` : m.username));
    if (m.role === "owner") row.appendChild(el("span", "role-tag", "Chủ nhóm"));
    if (isOwner && m.role !== "owner") {
      const b = el("button", "btn btn-small btn-ghost", "Xóa");
      b.addEventListener("click", () => removeMember(group, m));
      row.appendChild(b);
    }
    list.appendChild(row);
  }

  const addWrap = $("group-add-wrap");
  const addList = $("group-add-list");
  addList.replaceChildren();
  addWrap.classList.toggle("hidden", !isOwner);
  if (isOwner) {
    const candidates = state.friends.filter((f) => !group.members.some((m) => m.id === f.id));
    if (candidates.length === 0) addList.appendChild(el("div", "empty-hint", "Không còn bạn bè nào để thêm."));
    for (const f of candidates) {
      const row = el("div", "check-row");
      row.appendChild(el("span", "grow", f.username));
      const b = el("button", "btn btn-small btn-primary", "Thêm");
      b.addEventListener("click", () => addMember(group, f));
      row.appendChild(b);
      addList.appendChild(row);
    }
  }

  $("group-leave-btn").classList.toggle("hidden", isOwner);
  $("group-delete-btn").classList.toggle("hidden", !isOwner);
}

async function addMember(group, friend) {
  try {
    // Chủ nhóm gói khóa nhóm riêng cho người mới
    const raw = await getGroupRaw(group);
    const key = await getAesKey(friend);
    const wrapped = await encryptBytes(key, raw, wrapAad(state.me.id, friend.id));
    await api(`/groups/${group.id}/members`, { method: "POST", body: { user_id: friend.id, ...wrapped } });
    await loadGroups();
    renderGroupInfo();
    toast(`Đã thêm ${friend.username} vào nhóm`);
    sendSystem({ type: "group", id: group.id }, `${state.me.username} đã thêm ${friend.username} vào nhóm`);
  } catch (e) {
    toast(e.message);
  }
}

async function removeMember(group, member) {
  if (!confirm(`Xóa ${member.username} khỏi nhóm?`)) return;
  try {
    await api(`/groups/${group.id}/members/${member.id}`, { method: "DELETE" });
    await loadGroups();
    renderGroupInfo();
    sendSystem({ type: "group", id: group.id }, `${state.me.username} đã xóa ${member.username} khỏi nhóm`);
  } catch (e) {
    toast(e.message);
  }
}

async function leaveGroup() {
  const conv = state.current;
  if (!conv || conv.type !== "group") return;
  if (!confirm("Bạn muốn rời khỏi nhóm này?")) return;
  try {
    await sendSystem(conv, `${state.me.username} đã rời nhóm`);   // phải gửi trước khi rời
    await api(`/groups/${conv.id}/members/${state.me.id}`, { method: "DELETE" });
    closeModal("group-info-modal");
    closeChat();
    await loadGroups();
  } catch (e) {
    toast(e.message);
  }
}

async function deleteGroup() {
  const conv = state.current;
  if (!conv || conv.type !== "group") return;
  if (!confirm("Xóa nhóm này? Toàn bộ tin nhắn trong nhóm sẽ bị xóa vĩnh viễn.")) return;
  try {
    await api(`/groups/${conv.id}`, { method: "DELETE" });
    closeModal("group-info-modal");
    closeChat();
    await loadGroups();
  } catch (e) {
    toast(e.message);
  }
}

/* ============================ Hiển thị tin nhắn ============================ */

function showEmptyChat() {
  $("chat-panel").classList.add("hidden");
  $("chat-empty").classList.remove("hidden");
  $("chat-screen").classList.remove("in-chat");
}

function updateChatStatus() {
  if (!state.current) return;
  const s = $("chat-status");
  if (state.current.type === "dm") {
    const online = state.online.has(state.current.id);
    s.textContent = online ? "Đang online" : "Offline";
    s.classList.toggle("online", online);
  } else {
    const g = convRef(state.current);
    s.textContent = g ? `${g.members.length} thành viên` : "";
    s.classList.remove("online");
  }
}

function showTyping() {
  const s = $("chat-status");
  s.textContent = "đang nhập...";
  s.classList.add("online");
  clearTimeout(typingTimer);
  typingTimer = setTimeout(updateChatStatus, 3000);
}

/** Báo cho bạn biết mình đã xem tin (chỉ chat 1-1, và chỉ khi tab đang hiển thị). */
function markRead(friendId) {
  if (document.visibilityState !== "visible") return;
  if (state.socket && state.socket.connected) {
    state.socket.emit("mark_read", { with: friendId });
  }
}

/** Hiện chữ "Đã xem" dưới tin cuối cùng của mình mà bạn đã đọc. */
function renderSeen() {
  const box = $("messages");
  box.querySelectorAll(".seen-label").forEach((n) => n.remove());
  if (!state.current || state.current.type !== "dm") return;

  const mine = Array.from(box.querySelectorAll(".msg.me"));
  for (let i = mine.length - 1; i >= 0; i--) {
    if (mine[i].dataset.read === "1") {
      mine[i].insertAdjacentElement("afterend", el("div", "seen-label", "Đã xem"));
      break;
    }
  }
}

function clearMessages() {
  const box = $("messages");
  const loadMoreBtn = $("load-more");
  box.replaceChildren(loadMoreBtn);
  loadMoreBtn.classList.add("hidden");
}

function scrollToBottom() {
  const box = $("messages");
  box.scrollTop = box.scrollHeight;
}

/** Tải tệp/ảnh khi phần tử hiện ra màn hình (tránh tải hàng loạt khi mở cuộc chat). */
function lazyLoad(node, fn) {
  if (typeof IntersectionObserver === "undefined") { fn(); return; }
  if (!lazyObserver) {
    lazyObserver = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        lazyObserver.unobserve(e.target);
        const f = e.target._lazyFn;
        e.target._lazyFn = null;
        if (f) f();
      }
    }, { root: $("messages"), rootMargin: "200px" });
  }
  node._lazyFn = fn;
  lazyObserver.observe(node);
}

function renderFile(conv, body, msg, res) {
  const meta = res.meta;

  if (IMAGE_TYPES.includes(meta.type)) {
    const holder = el("div", "img-holder", "🖼 Đang tải ảnh...");
    body.appendChild(holder);
    const show = (blob) => {
      const url = URL.createObjectURL(blob);
      const img = el("img", "msg-img");
      img.src = url;
      img.alt = meta.name;
      img.addEventListener("click", () => window.open(url, "_blank", "noopener"));
      holder.replaceChildren(img);
    };
    if (res.localBlob) show(res.localBlob);
    else lazyLoad(holder, async () => {
      try { show(await fetchFileBlob(conv, msg, meta)); }
      catch (e) { holder.textContent = "⚠ " + e.message; }
    });
  }

  const card = el("div", "file-card");
  card.appendChild(el("span", "file-name", `📎 ${meta.name}`));
  card.appendChild(el("span", "file-size", formatSize(meta.size)));
  const btn = el("button", "btn btn-small btn-ghost file-dl", "Tải xuống");
  btn.type = "button";
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      const blob = res.localBlob || (await fetchFileBlob(conv, msg, meta));
      downloadBlob(blob, meta.name);
    } catch (e) {
      toast(e.message);
    } finally {
      btn.disabled = false;
    }
  });
  card.appendChild(btn);
  body.appendChild(card);
}

function fillBody(conv, div, body, msg, res) {
  body.replaceChildren();
  if (msg.deleted || res.deleted) {
    div.classList.add("recalled");
    body.textContent = "Tin nhắn đã bị thu hồi";
    return;
  }
  if (!res.ok) {
    div.classList.add("error");
    body.textContent = "⚠ Không giải mã được tin nhắn này";
    return;
  }
  if (res.kind === "file") renderFile(conv, body, msg, res);
  else appendLinkified(body, res.text);
}

function buildActions(conv, msg, mine) {
  const box = el("div", "msg-actions");
  if (mine && !msg.deleted) {
    const r = el("button", "action-btn action-recall", "Thu hồi");
    r.type = "button";
    r.addEventListener("click", () => recallMessage(conv, msg.id));
    box.appendChild(r);
  }
  const d = el("button", "action-btn", "Xóa với tôi");
  d.type = "button";
  d.addEventListener("click", () => deleteForMe(conv, msg.id));
  box.appendChild(d);
  return box;
}

function buildMessageEl(conv, msg, res) {
  const mine = msg.sender_id === state.me.id;

  if (msg.kind === "system" && !msg.deleted) {
    const d = el("div", "system-msg", res.ok ? res.text : "⚠ Không giải mã được thông báo");
    d.dataset.mid = String(msg.id);
    return d;
  }

  const div = el("div", `msg ${mine ? "me" : "them"}`);
  div.dataset.mid = String(msg.id);
  div.dataset.read = msg.read_at ? "1" : "0";

  if (conv.type === "group" && !mine) {
    div.appendChild(el("span", "msg-sender", senderName(conv, msg.sender_id)));
  }

  const body = el("div", "msg-body");
  div.appendChild(body);
  fillBody(conv, div, body, msg, res);

  div.appendChild(el("span", "msg-time", formatTime(msg.created_at)));
  div.appendChild(buildActions(conv, msg, mine));

  // Chạm vào tin để hiện nút Thu hồi/Xóa (dùng trên điện thoại, không có chuột rê)
  div.addEventListener("click", (e) => {
    if (e.target.closest("a, button, img")) return;
    div.classList.toggle("show-actions");
  });
  return div;
}

function appendMessage(conv, msg, res) {
  $("messages").appendChild(buildMessageEl(conv, msg, res));
}

/* ============================ Mở cuộc trò chuyện ============================ */

function historyRequest(conv, beforeId) {
  return conv.type === "dm"
    ? ["get_history", { with: conv.id, before_id: beforeId }]
    : ["get_group_history", { group_id: conv.id, before_id: beforeId }];
}

async function fetchHistory(conv, beforeId) {
  const [event, args] = historyRequest(conv, beforeId);
  const res = await emitAck(event, args);
  if (!res.ok) throw new Error(res.error || "Không tải được lịch sử");
  return res.messages;
}

async function openChat(type, id) {
  const conv = { type, id };
  const ref = convRef(conv);
  if (!ref) return;

  state.current = conv;
  state.unread[convKey(conv)] = 0;
  state.oldestId = null;
  const loadId = ++state.chatLoadId;

  $("chat-empty").classList.add("hidden");
  $("chat-panel").classList.remove("hidden");
  $("chat-screen").classList.add("in-chat");
  $("chat-title").textContent = type === "dm" ? ref.username : ref.name;
  const avatar = $("chat-avatar");
  avatar.textContent = type === "dm" ? initial(ref.username) : "👥";
  avatar.classList.toggle("group-avatar", type === "group");
  $("chat-fingerprint").textContent = type === "dm" ? "🔑 ..." : "🔑 Khóa nhóm AES-256";
  $("group-info-btn").classList.toggle("hidden", type !== "group");
  closeSearch();
  clearMessages();
  updateChatStatus();
  renderFriends();
  renderGroups();
  $("message-input").focus();

  try {
    await getConvKey(conv);
    if (type === "dm") {
      const fp = await fingerprint(state.me.public_key, ref.public_key);
      if (loadId !== state.chatLoadId) return;
      $("chat-fingerprint").textContent = `🔑 ${fp}`;
    }

    const messages = await fetchHistory(conv, null);
    if (loadId !== state.chatLoadId) return;

    for (const msg of messages) {
      const res = await decryptMessage(conv, msg);
      if (loadId !== state.chatLoadId) return;
      appendMessage(conv, msg, res);
    }
    state.oldestId = messages.length ? messages[0].id : null;
    $("load-more").classList.toggle("hidden", messages.length < HISTORY_LIMIT);
    scrollToBottom();
    renderSeen();
    if (type === "dm") markRead(id);
  } catch (err) {
    toast(err.message);
  }
}

async function loadMore() {
  const conv = state.current;
  if (!conv || state.oldestId === null) return;
  const loadId = state.chatLoadId;

  try {
    const messages = await fetchHistory(conv, state.oldestId);
    if (loadId !== state.chatLoadId) return;

    const box = $("messages");
    const prevHeight = box.scrollHeight;
    const frag = document.createDocumentFragment();
    for (const msg of messages) {
      frag.appendChild(buildMessageEl(conv, msg, await decryptMessage(conv, msg)));
    }
    box.insertBefore(frag, $("load-more").nextSibling);
    box.scrollTop += box.scrollHeight - prevHeight;

    if (messages.length) state.oldestId = messages[0].id;
    $("load-more").classList.toggle("hidden", messages.length < HISTORY_LIMIT);
  } catch (err) {
    toast(err.message);
  }
}

function closeChat() {
  state.current = null;
  state.chatLoadId++;
  closeSearch();
  showEmptyChat();
  renderFriends();
  renderGroups();
}

/* ============================ Gửi tin, tệp ============================ */

async function onSendMessage(e) {
  e.preventDefault();
  const conv = state.current;
  const input = $("message-input");
  const text = input.value.trim();
  if (!conv || !text) return;
  input.value = "";

  try {
    await sendText(conv, text);
  } catch (err) {
    toast(err.message);
    input.value = text;   // trả lại nội dung để người dùng gửi lại
  }
}

async function onFileChosen(e) {
  const file = e.target.files[0];
  e.target.value = "";
  const conv = state.current;
  if (!file || !conv) return;

  if (file.size > MAX_FILE_BYTES) {
    toast(`Tệp quá lớn (tối đa ${formatSize(MAX_FILE_BYTES)})`);
    return;
  }
  if (file.size === 0) {
    toast("Tệp rỗng");
    return;
  }

  const btn = $("attach-btn");
  btn.disabled = true;
  toast("Đang mã hóa và gửi tệp...");
  try {
    await sendFile(conv, file);
  } catch (err) {
    toast(err.message);
  } finally {
    btn.disabled = false;
  }
}

/* ============================ Thu hồi / xóa ============================ */

async function recallMessage(conv, id) {
  const who = conv.type === "dm" ? "cả hai bên" : "mọi người trong nhóm";
  if (!confirm(`Thu hồi tin nhắn này? Nội dung sẽ bị xóa với ${who}.`)) return;
  try {
    const r = await emitAck("recall_message", { scope: scopeOf(conv), id });
    if (!r.ok) throw new Error(r.error || "Không thu hồi được");
    // Giao diện được cập nhật khi nhận sự kiện "message_recalled"
  } catch (e) {
    toast(e.message);
  }
}

function markRecalled(id) {
  const node = $("messages").querySelector(`[data-mid="${id}"]`);
  if (!node) return;
  node.classList.add("recalled");
  node.classList.remove("error", "show-actions");
  const body = node.querySelector(".msg-body");
  if (body) body.textContent = "Tin nhắn đã bị thu hồi";
  const btn = node.querySelector(".action-recall");
  if (btn) btn.remove();
}

async function deleteForMe(conv, id) {
  if (!confirm("Xóa tin nhắn này khỏi lịch sử của bạn? Người khác vẫn còn thấy.")) return;
  try {
    const r = await emitAck("delete_for_me", { scope: scopeOf(conv), id });
    if (!r.ok) throw new Error(r.error || "Không xóa được");
    const node = $("messages").querySelector(`[data-mid="${id}"]`);
    if (node) node.remove();
    renderSeen();
  } catch (e) {
    toast(e.message);
  }
}

/* ============================ Tìm kiếm tin nhắn ============================ */
// Server chỉ có bản mã nên không tìm được. Trình duyệt tải lịch sử, giải mã rồi tự lọc.

function openSearch() {
  if (!state.current) return;
  $("search-panel").classList.remove("hidden");
  $("msg-search-input").focus();
}

function closeSearch() {
  searchSeq++;
  $("search-panel").classList.add("hidden");
  $("msg-search-input").value = "";
  $("msg-search-filter").value = "all";
  $("msg-search-status").textContent = "";
  $("msg-search-results").replaceChildren();
}

async function fetchAllHistory(conv) {
  const all = [];
  let before = null;
  while (all.length < SEARCH_CAP) {
    const page = await fetchHistory(conv, before);
    if (page.length === 0) break;
    all.unshift(...page);
    before = page[0].id;
    if (page.length < HISTORY_LIMIT) break;
  }
  return all;
}

async function runMessageSearch() {
  const conv = state.current;
  if (!conv) return;
  const q = $("msg-search-input").value.trim().toLowerCase();
  const filter = $("msg-search-filter").value;
  const status = $("msg-search-status");
  const box = $("msg-search-results");
  box.replaceChildren();

  if (!q && filter === "all") {
    status.textContent = "Nhập từ khóa hoặc chọn bộ lọc Liên kết / Ảnh và tệp.";
    return;
  }

  const mySeq = ++searchSeq;
  const key = convKey(conv);
  status.textContent = "Đang giải mã và tìm trên máy bạn...";

  try {
    const all = await fetchAllHistory(conv);
    const hits = [];
    for (let i = all.length - 1; i >= 0 && hits.length < 100; i--) {    // mới nhất trước
      const msg = all[i];
      if (msg.deleted || msg.kind === "system") continue;
      const res = await decryptMessage(conv, msg);
      if (!res.ok) continue;

      const isFile = res.kind === "file";
      const haystack = isFile ? res.meta.name : res.text;
      const hasLink = !isFile && splitLinks(res.text).some((p) => p.type === "link");

      if (filter === "links" && !hasLink) continue;
      if (filter === "files" && !isFile) continue;
      if (q && !haystack.toLowerCase().includes(q)) continue;
      hits.push({ msg, label: isFile ? `📎 ${haystack}` : haystack });
    }

    if (mySeq !== searchSeq || !state.current || convKey(state.current) !== key) return;

    status.textContent = hits.length
      ? `Tìm thấy ${hits.length}${hits.length >= 100 ? "+" : ""} kết quả (quét ${all.length} tin nhắn)`
      : `Không có kết quả (đã quét ${all.length} tin nhắn)`;

    for (const h of hits) {
      const row = el("div", "search-hit");
      row.appendChild(el("div", "hit-meta", `${senderName(conv, h.msg.sender_id)} · ${formatTime(h.msg.created_at)}`));
      row.appendChild(el("div", "hit-text", h.label.slice(0, 160)));
      row.addEventListener("click", () => jumpToMessage(h.msg.id));
      box.appendChild(row);
    }
  } catch (e) {
    status.textContent = "Lỗi: " + e.message;
  }
}

/** Cuộn tới 1 tin nhắn; nếu chưa được tải thì tải thêm tin cũ cho tới khi gặp. */
async function jumpToMessage(id) {
  for (let i = 0; i < 60; i++) {
    const node = $("messages").querySelector(`[data-mid="${id}"]`);
    if (node) {
      node.scrollIntoView({ block: "center" });
      node.classList.add("flash");
      setTimeout(() => node.classList.remove("flash"), 1800);
      return;
    }
    if ($("load-more").classList.contains("hidden")) break;
    await loadMore();
  }
  toast("Không tìm thấy tin nhắn này trong khung chat");
}

/* ============================ Khởi động ============================ */

async function init() {
  if (!window.crypto || !crypto.subtle) {
    showAuth("Trình duyệt không hỗ trợ Web Crypto. Hãy mở bằng http://localhost:5000 hoặc HTTPS.");
    $("auth-submit").disabled = true;
    return;
  }

  $("tab-login").addEventListener("click", () => setMode("login"));
  $("tab-register").addEventListener("click", () => setMode("register"));
  $("auth-form").addEventListener("submit", onAuthSubmit);
  $("logout-btn").addEventListener("click", logout);
  $("message-form").addEventListener("submit", onSendMessage);
  $("load-more").addEventListener("click", loadMore);
  $("back-btn").addEventListener("click", closeChat);
  $("search-input").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(runSearch, 300);
  });

  // Tệp đính kèm
  $("attach-btn").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", onFileChosen);

  // Tìm kiếm trong cuộc trò chuyện
  $("search-toggle").addEventListener("click", openSearch);
  $("msg-search-close").addEventListener("click", closeSearch);
  $("msg-search-go").addEventListener("click", runMessageSearch);
  $("msg-search-filter").addEventListener("change", runMessageSearch);
  $("msg-search-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); runMessageSearch(); }
  });

  // Nhóm
  $("new-group-btn").addEventListener("click", openGroupModal);
  $("group-modal-close").addEventListener("click", () => closeModal("group-modal"));
  $("group-create-btn").addEventListener("click", createGroup);
  $("group-info-btn").addEventListener("click", openGroupInfo);
  $("group-info-close").addEventListener("click", () => closeModal("group-info-modal"));
  $("group-leave-btn").addEventListener("click", leaveGroup);
  $("group-delete-btn").addEventListener("click", deleteGroup);
  for (const id of ["group-modal", "group-info-modal"]) {
    $(id).addEventListener("click", (e) => { if (e.target === $(id)) closeModal(id); });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeModal("group-modal"); closeModal("group-info-modal"); }
  });

  // Gửi tín hiệu "đang nhập" (chỉ chat 1-1, tối đa 1 lần / 2 giây)
  $("message-input").addEventListener("input", () => {
    if (!state.current || state.current.type !== "dm") return;
    if (!state.socket || !state.socket.connected) return;
    const now = Date.now();
    if (now - lastTypingSent > 2000) {
      lastTypingSent = now;
      state.socket.emit("typing", { to: state.current.id });
    }
  });

  // Quay lại tab thì coi như đã xem các tin mới
  document.addEventListener("visibilitychange", () => {
    if (state.current && state.current.type === "dm") markRead(state.current.id);
  });

  // Khôi phục phiên đăng nhập cũ nếu còn token
  const token = localStorage.getItem(TOKEN_KEY);
  const userStr = localStorage.getItem(USER_KEY);
  if (token && userStr) {
    try {
      await startApp(token, JSON.parse(userStr));
      return;
    } catch (err) {
      logout();
      showAuth(err.message);
      return;
    }
  }
  showAuth();
}

init();
