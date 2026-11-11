const express = require("express");
const fs = require("fs");
const { sign, getRole } = require("./jwt");
require("./backend");

const app = express();
app.use(express.urlencoded({ extended: false }));

function api(method, path, body, token) {
  return fetch("http://127.0.0.1:4000" + path, {
    method: method,
    headers: { "X-Token": encodeURIComponent(token || "") },
    body: body ? JSON.stringify(body) : undefined
  });
}

function escapeHtml(text) {
  return String(text).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function render(name, values) {
  let html = fs.readFileSync(__dirname + "/views/" + name + ".html", "utf8");
  for (const key in values) {
    html = html.split("{{" + key + "}}").join(values[key]);
  }
  return html;
}

function getCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const pair = part.trim().split("=");
    if (pair[0] === name) return pair[1];
  }
  return "";
}

// XSS mice HttpOnly flag
function setCookie(res, token, settings) {
  res.setHeader("Set-Cookie", "token=" + token + "; Path=/" + (settings.xssVulnerable ? "" : "; HttpOnly"));
}

function page(req, content) {
  return render("layout", {
    token: escapeHtml(req.token),
    role: req.role,
    xssChecked: req.settings.xssVulnerable ? "checked" : "",
    accessChecked: req.settings.accessVulnerable ? "checked" : "",
    content: content
  });
}

// Svaki posjetitelj dobiva cookie
app.use(async function (req, res, next) {
  req.settings = await (await api("GET", "/api/settings")).json();
  req.token = getCookie(req, "token");
  if (!req.token) {
    req.token = sign({ role: "user" });
    setCookie(res, req.token, req.settings);
  }
  req.role = getRole(req.token, !req.settings.accessVulnerable);
  next();
});

app.get("/", function (req, res) {
  res.send(page(req, render("home", {})));
});

// XSS
app.get("/recenzija", async function (req, res) {
  const messages = await (await api("GET", "/api/messages")).json();
  let list = "";
  for (const m of messages) {
    const text = req.settings.xssVulnerable ? m.text : escapeHtml(m.text);
    list += "<p><b>" + escapeHtml(m.author) + ":</b> " + text + "</p>";
  }
  res.send(page(req, render("recenzija", { messages: list })));
});

app.post("/recenzija", async function (req, res) {
  await api("POST", "/api/messages", { author: "posjetitelj (" + req.role + ")", text: String(req.body.message) });
  res.redirect("/recenzija");
});

app.post("/recenzija/clear", async function (req, res) {
  await api("DELETE", "/api/messages");
  res.redirect("/recenzija");
});

// Kontrola pristupa
app.get("/admin", async function (req, res) {
  const result = await api("GET", "/api/admin", null, req.token);
  if (result.status !== 200) {
    return res.status(403).send(page(req, "<h2>403 Zabranjeno</h2><p>Admin panel je dostupan samo s tokenom u kojem je role=admin.</p>"));
  }
  let rows = "";
  for (const e of await result.json()) {
    rows += "<tr><td>" + e.id + "</td><td>" + escapeHtml(e.name) + "</td><td>" + escapeHtml(e.secret) + "</td></tr>";
  }
  res.send(page(req, render("admin", { rows: rows })));
});

app.post("/settings", async function (req, res) {
  const settings = await (await api("POST", "/api/settings", {
    xssVulnerable: req.body.xss === "on",
    accessVulnerable: req.body.access === "on"
  })).json();
  setCookie(res, req.token, settings);
  res.redirect("/");
});

// izdaje ispravno potpisan token za user ili admin
app.post("/role", function (req, res) {
  setCookie(res, sign({ role: req.body.role === "admin" ? "admin" : "user" }), req.settings);
  res.redirect("/");
});

app.listen(process.env.PORT || 3000);
