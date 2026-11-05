"use strict";

/* =====================================================================
 *  SecureChat - logic phía trình duyệt
 *  Mã hóa đầu cuối:
 *    1. Mỗi user có cặp khóa ECDH P-256. Khóa bí mật nằm trong localStorage
 *       của trình duyệt, chỉ khóa công khai được gửi lên server.
 *    2. Với mỗi người bạn: ECDH(khóa bí mật của mình, khóa công khai của bạn)
 *       -> bí mật chung -> HKDF-SHA256 -> khóa AES-256-GCM.
 *    3. Mỗi tin nhắn được mã hóa bằng AES-GCM với IV ngẫu nhiên 12 byte.
 *       Server chỉ thấy ciphertext + iv.
 * ===================================================================== */

const API = "/api";
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const HISTORY_LIMIT = 50;
const POLL_MS = 10000;

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
  online: new Set(),
  unread: {},             // friendId -> số tin chưa đọc
  current: null,          // bạn đang chat
  aesKeys: new Map(),     // friendId -> CryptoKey (AES-GCM)
  oldestId: null,
  chatLoadId: 0,          // chống lẫn dữ liệu khi đổi cuộc chat nhanh
};

let pollTimer = null;
let searchTimer = null;
let toastTimer = null;

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
  const d = new Date(sqlDate.replace(" ", "T") + "Z");
  if (isNaN(d)) return "";
  const time = d.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === new Date().toDateString()
    ? time
    : `${time} ${d.toLocaleDateString("vi-VN")}`;
}

const b64 = {
  encode(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  },
  decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

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

// additionalData gắn người gửi và người nhận vào bản mã, để server không thể
// đảo chiều hoặc giả mạo người gửi mà không bị phát hiện.
const aad = (senderId, receiverId) => enc.encode(`${senderId}:${receiverId}`);

async function encryptText(key, text, senderId, receiverId) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(senderId, receiverId) },
    key,
    enc.encode(text)
  );
  return { ciphertext: b64.encode(ct), iv: b64.encode(iv) };
}

async function decryptText(key, msg) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64.decode(msg.iv), additionalData: aad(msg.sender_id, msg.receiver_id) },
    key,
    b64.decode(msg.ciphertext)
  );
  return dec.decode(plain);
}

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

/* ============================ Gọi API ============================ */

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

function emitAck(event, data) {
  return new Promise((resolve, reject) => {
    if (!state.socket || !state.socket.connected) {
      return reject(new Error("Mất kết nối tới server"));
    }
    const timer = setTimeout(() => reject(new Error("Server phản hồi quá lâu")), 10000);
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
  state.unread = {};

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
  state.online = new Set();
  state.current = null;
  state.aesKeys.clear();
  clearSession();
  $("friends-list").replaceChildren();
  $("search-results").replaceChildren();
  $("search-input").value = "";
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

  socket.on("new_message", (msg) => handleIncoming(msg));
}

async function handleIncoming(msg) {
  const mine = msg.sender_id === state.me.id;
  const friendId = mine ? msg.receiver_id : msg.sender_id;

  let friend = state.friends.find((f) => f.id === friendId);
  if (!friend) {
    await loadFriends();
    friend = state.friends.find((f) => f.id === friendId);
    if (!friend) return;
  }

  if (state.current && state.current.id === friendId) {
    const { text, ok } = await decryptMessage(friend, msg);
    appendMessage(msg, text, ok);
    scrollToBottom();
  } else if (!mine) {
    state.unread[friendId] = (state.unread[friendId] || 0) + 1;
    renderFriends();
  }
}

/* ============================ Bạn bè & lời mời ============================ */

async function refreshSocial() {
  await Promise.all([loadFriends(), loadRequests()]);
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
    const row = el("div", "friend-item" + (state.current && state.current.id === f.id ? " active" : ""));
    row.appendChild(el("div", "avatar", initial(f.username)));
    row.appendChild(el("span", "friend-name", f.username));

    const unread = state.unread[f.id] || 0;
    if (unread > 0) row.appendChild(el("span", "unread", String(unread)));

    row.appendChild(el("span", "status-dot" + (state.online.has(f.id) ? " online" : "")));
    row.addEventListener("click", () => openChat(f));
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

/* ============================ Khung chat ============================ */

function showEmptyChat() {
  $("chat-panel").classList.add("hidden");
  $("chat-empty").classList.remove("hidden");
  $("chat-screen").classList.remove("in-chat");
}

function updateChatStatus() {
  if (!state.current) return;
  const online = state.online.has(state.current.id);
  const s = $("chat-status");
  s.textContent = online ? "Đang online" : "Offline";
  s.classList.toggle("online", online);
}

function clearMessages() {
  const box = $("messages");
  const loadMore = $("load-more");
  box.replaceChildren(loadMore);
  loadMore.classList.add("hidden");
}

function scrollToBottom() {
  const box = $("messages");
  box.scrollTop = box.scrollHeight;
}

async function decryptMessage(friend, msg) {
  try {
    const key = await getAesKey(friend);
    return { text: await decryptText(key, msg), ok: true };
  } catch {
    return { text: "", ok: false };
  }
}

function buildMessageEl(msg, text, ok) {
  const mine = msg.sender_id === state.me.id;
  const div = el("div", `msg ${mine ? "me" : "them"}${ok ? "" : " error"}`);
  div.appendChild(document.createTextNode(ok ? text : "⚠ Không giải mã được tin nhắn này"));
  div.appendChild(el("span", "msg-time", formatTime(msg.created_at)));
  return div;
}

function appendMessage(msg, text, ok = true) {
  $("messages").appendChild(buildMessageEl(msg, text, ok));
}

async function openChat(friend) {
  state.current = friend;
  state.unread[friend.id] = 0;
  state.oldestId = null;
  const loadId = ++state.chatLoadId;

  $("chat-empty").classList.add("hidden");
  $("chat-panel").classList.remove("hidden");
  $("chat-screen").classList.add("in-chat");
  $("chat-title").textContent = friend.username;
  $("chat-avatar").textContent = initial(friend.username);
  $("chat-fingerprint").textContent = "🔑 ...";
  clearMessages();
  updateChatStatus();
  renderFriends();
  $("message-input").focus();

  try {
    await getAesKey(friend);
    const fp = await fingerprint(state.me.public_key, friend.public_key);
    if (loadId !== state.chatLoadId) return;
    $("chat-fingerprint").textContent = `🔑 ${fp}`;

    const res = await emitAck("get_history", { with: friend.id });
    if (loadId !== state.chatLoadId) return;
    if (!res.ok) throw new Error(res.error || "Không tải được lịch sử");

    for (const msg of res.messages) {
      const { text, ok } = await decryptMessage(friend, msg);
      if (loadId !== state.chatLoadId) return;
      appendMessage(msg, text, ok);
    }
    state.oldestId = res.messages.length ? res.messages[0].id : null;
    $("load-more").classList.toggle("hidden", res.messages.length < HISTORY_LIMIT);
    scrollToBottom();
  } catch (err) {
    toast(err.message);
  }
}

async function loadMore() {
  const friend = state.current;
  if (!friend || state.oldestId === null) return;
  const loadId = state.chatLoadId;

  try {
    const res = await emitAck("get_history", { with: friend.id, before_id: state.oldestId });
    if (loadId !== state.chatLoadId) return;
    if (!res.ok) throw new Error(res.error || "Không tải được tin cũ");

    const box = $("messages");
    const prevHeight = box.scrollHeight;
    const frag = document.createDocumentFragment();
    for (const msg of res.messages) {
      const { text, ok } = await decryptMessage(friend, msg);
      frag.appendChild(buildMessageEl(msg, text, ok));
    }
    box.insertBefore(frag, $("load-more").nextSibling);
    box.scrollTop += box.scrollHeight - prevHeight;

    if (res.messages.length) state.oldestId = res.messages[0].id;
    $("load-more").classList.toggle("hidden", res.messages.length < HISTORY_LIMIT);
  } catch (err) {
    toast(err.message);
  }
}

async function onSendMessage(e) {
  e.preventDefault();
  const friend = state.current;
  const input = $("message-input");
  const text = input.value.trim();
  if (!friend || !text) return;
  input.value = "";

  try {
    const key = await getAesKey(friend);
    const { ciphertext, iv } = await encryptText(key, text, state.me.id, friend.id);
    const res = await emitAck("send_message", { to: friend.id, ciphertext, iv });
    if (!res.ok) throw new Error(res.error || "Gửi thất bại");

    if (state.current && state.current.id === friend.id) {
      appendMessage(res.message, text, true);
      scrollToBottom();
    }
  } catch (err) {
    toast(err.message);
    input.value = text;   // trả lại nội dung để người dùng gửi lại
  }
}

function closeChat() {
  state.current = null;
  state.chatLoadId++;
  showEmptyChat();
  renderFriends();
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
