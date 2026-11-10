const express = require("express");
const fs = require("fs");
require("./backend");

const app = express();
app.use(express.urlencoded({ extended: false }));

function api(method, path, body, role) {
  return fetch("http://127.0.0.1:4000" + path, {
    method: method,
    headers: { "X-Role": encodeURIComponent(role || "") },
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

//AKO JE XSS onda se cookie moze procitati jer nema HttpOnlyFlag
function setRole(res, role, settings) {
  res.setHeader("Set-Cookie", "role=" + role + "; Path=/" + (settings.xssVulnerable ? "" : "; HttpOnly"));
}

function page(req, content) {
  return render("layout", {
    role: req.role,
    xssChecked: req.settings.xssVulnerable ? "checked" : "",
    accessChecked: req.settings.accessVulnerable ? "checked" : "",
    content: content
  });
}

//Svaki korisnik dobiva cookie role=user
app.use(async function (req, res, next) {
  req.settings = await (await api("GET", "/api/settings")).json();
  const cookie = req.headers.cookie || "";
  req.role = cookie.includes("role=admin") ? "admin" : "user";
  if (!cookie.includes("role=")) setRole(res, "user", req.settings);
  next();
});

app.get("/", function (req, res) {
  res.send(page(req, render("home", {})));
});

// XSS
app.get("/guestbook", async function (req, res) {
  const messages = await (await api("GET", "/api/messages")).json();
  let list = "";
  for (const m of messages) {
    const text = req.settings.xssVulnerable ? m.text : escapeHtml(m.text);
    list += "<p><b>" + escapeHtml(m.author) + ":</b> " + text + "</p>";
  }
  res.send(page(req, render("guestbook", { messages: list })));
});

app.post("/guestbook", async function (req, res) {
  await api("POST", "/api/messages", { author: "posjetitelj", text: String(req.body.message) });
  res.redirect("/guestbook");
});

app.post("/guestbook/clear", async function (req, res) {
  await api("DELETE", "/api/messages");
  res.redirect("/guestbook");
});

// Kontrola
app.get("/admin", async function (req, res) {
  const result = await api("GET", "/api/admin", null, req.role);
  if (result.status !== 200) {
    return res.status(403).send(page(req, "<h2>403 Zabranjeno</h2><p>Admin panel je dostupan samo s kolačićem role=admin.</p>"));
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
  setRole(res, req.role, settings);
  res.redirect("/");
});

app.post("/role", function (req, res) {
  setRole(res, req.body.role === "admin" ? "admin" : "user", req.settings);
  res.redirect("/");
});

app.listen(process.env.PORT || 3000);
