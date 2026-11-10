const http = require("http");

const settings = { xssVulnerable: true, accessVulnerable: true };
let messages = []
const names = ["STRIPE_API_KEY", "WIFI_PASS", "JWT_SECRET", "ADMIN_PASSWORD"];
const secrets = names.map(function (name, i) {
  return { id: i + 1, name: name, secret: process.env[name] };
});

function handle(method, url, body, role) {
  if (method === "GET" && url === "/api/settings") {
    return [200, settings];
  }
  if (method === "POST" && url === "/api/settings") {
    settings.xssVulnerable = body.xssVulnerable === true;
    settings.accessVulnerable = body.accessVulnerable === true;
    return [200, settings];
  }
  if (method === "GET" && url === "/api/messages") {
    return [200, messages];
  }
  if (method === "POST" && url === "/api/messages") {
    messages.push({ author: String(body.author), text: String(body.text) });
    return [201, { ok: true }];
  }
  if (method === "DELETE" && url === "/api/messages") {
    messages = []
    return [200, { ok: true }];
  }
  if (method === "GET" && url === "/api/admin") {

    if (!settings.accessVulnerable && role !== "admin") {
      return [403, { error: "Zabranjeno" }];
    }
    return [200, secrets];
  }
  return [404, { error: "Nije pronađeno" }];
}

http.createServer(function (req, res) {
  let raw = "";
  req.on("data", function (chunk) { raw += chunk; });
  req.on("end", function () {
    let status, result;
    try {
      const body = raw ? JSON.parse(raw) : {};
      const role = decodeURIComponent(req.headers["x-role"] || "");
      [status, result] = handle(req.method, req.url, body, role);
    } catch (e) {
      status = 400;
      result = { error: "Neispravan zahtjev" };
    }
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  });
}).listen(4000, "127.0.0.1");