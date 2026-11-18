"use strict";

const authView = document.getElementById("auth-view");
const homeView = document.getElementById("home-view");
const form = document.getElementById("auth-form");
const authFields = document.getElementById("auth-fields");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const confirmGroup = document.getElementById("confirm-group");
const confirmInput = document.getElementById("confirm-password");
const showPasswordButton = document.getElementById("show-password");
const message = document.getElementById("message");
const submitButton = document.getElementById("submit-button");
const passwordHint = document.getElementById("password-hint");
const loginTab = document.getElementById("login-tab");
const registerTab = document.getElementById("register-tab");
const logoutButton = document.getElementById("logout-button");
const welcome = document.getElementById("welcome");
const retryButton = document.getElementById("retry-button");

let mode = "login";
let csrfToken = "";

async function api(url, options = {}) {
  const unavailable = "Server se connection nahi hua. Project folder mein npm start karke dobara koshish karein.";
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  }).catch(() => { throw new Error(unavailable); });

  const data = await response.json().catch(() => null);
  if (!data) throw new Error(unavailable);

  if (!response.ok) {
    const error = new Error(data.error || "Request complete nahi hui.");
    error.code = data.code;
    throw error;
  }

  return data;
}

async function refreshCsrfToken() {
  const data = await api("/api/csrf");
  csrfToken = data.csrfToken;
  return data;
}

async function post(url, body) {
  if (!csrfToken) await refreshCsrfToken();
  const send = () => api(url, {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify(body)
  });
  try {
    return await send();
  } catch (error) {
    // The server checks CSRF before it changes an account or session.
    if (error.code !== "CSRF") throw error;
    await refreshCsrfToken();
    return send();
  }
}

function setMode(nextMode) {
  mode = nextMode;
  const isRegister = mode === "register";

  loginTab.classList.toggle("active", !isRegister);
  registerTab.classList.toggle("active", isRegister);
  loginTab.setAttribute("aria-pressed", String(!isRegister));
  registerTab.setAttribute("aria-pressed", String(isRegister));

  confirmGroup.hidden = !isRegister;
  confirmInput.disabled = !isRegister;
  confirmInput.required = isRegister;
  confirmInput.value = "";
  confirmInput.type = "password";
  confirmInput.removeAttribute("aria-invalid");
  passwordHint.hidden = !isRegister;
  if (isRegister) passwordInput.setAttribute("aria-describedby", "password-hint");
  else passwordInput.removeAttribute("aria-describedby");
  passwordInput.autocomplete = isRegister
    ? "new-password"
    : "current-password";

  passwordInput.minLength = isRegister ? 12 : 1;
  submitButton.textContent = isRegister
    ? "Account banayein"
    : "Login karein";

  message.textContent = "";
  passwordInput.value = "";
  passwordInput.type = "password";
  showPasswordButton.textContent = "Password dikhayein";
}

function showUser(username) {
  message.textContent = "";
  authView.hidden = true;
  homeView.hidden = false;
  welcome.textContent = `Namaste, ${username}!`;
  welcome.focus();
}

function showAuth() {
  homeView.hidden = true;
  authView.hidden = false;
  authFields.disabled = false;
  form.reset();
  setMode("login");
  usernameInput.focus();
}

loginTab.addEventListener("click", () => {
  setMode("login");
});

registerTab.addEventListener("click", () => {
  setMode("register");
});

showPasswordButton.addEventListener("click", () => {
  const passwordVisible = passwordInput.type === "text";
  passwordInput.type = passwordVisible ? "password" : "text";
  confirmInput.type = passwordInput.type;

  showPasswordButton.textContent = passwordVisible
    ? "Password dikhayein"
    : "Password chupayein";
});

form.addEventListener("input", () => {
  confirmInput.removeAttribute("aria-invalid");
  message.textContent = "";
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (authFields.disabled) return;
  message.textContent = "";

  if (mode === "register" && passwordInput.value !== confirmInput.value) {
    message.textContent = "Dono passwords alag hain. Dobara wahi password daalein.";
    confirmInput.setAttribute("aria-invalid", "true");
    confirmInput.focus();
    return;
  }

  authFields.disabled = true;
  try {
    const endpoint =
      mode === "register"
        ? "/api/register"
        : "/api/login";

    const data = await post(endpoint, {
      username: usernameInput.value.trim(),
      password: passwordInput.value
    });

    csrfToken = data.csrfToken;
    form.reset();
    showUser(data.user.username);
  } catch (error) {
    message.textContent =
      error.message || "Kuch galat ho gaya.";
  } finally {
    authFields.disabled = false;
  }
});

logoutButton.addEventListener("click", async () => {
  if (logoutButton.disabled) return;
  logoutButton.disabled = true;
  message.textContent = "";

  try {
    await post("/api/logout", {});
    csrfToken = "";
    showAuth();
  } catch (error) {
    message.textContent =
      error.message || "Logout nahi ho saka.";
  } finally {
    logoutButton.disabled = false;
  }
});

async function start() {
  authFields.disabled = true;
  retryButton.hidden = true;
  if (location.protocol === "file:") {
    message.textContent = "Project folder mein npm start chalayein, phir terminal mein diya address browser mein kholen.";
    return;
  }
  message.textContent = "Server se jud rahe hain…";
  try {
    await refreshCsrfToken();
    const data = await api("/api/me");

    if (data.user) {
      showUser(data.user.username);
    } else {
      showAuth();
    }
  } catch (error) {
    message.textContent = error.message;
    retryButton.hidden = false;
  }
}

retryButton.addEventListener("click", start);
start();
