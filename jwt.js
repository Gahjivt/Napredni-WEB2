const crypto = require("crypto");

function base64url(text) {
  return Buffer.from(text).toString("base64url");
}

function hmac(data) {
  return crypto.createHmac("sha256", process.env.JWT_SECRET).update(data).digest("base64url");
}

function sign(payload) {
  const data = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" })) + "." + base64url(JSON.stringify(payload));
  return data + "." + hmac(data);
}

// Vraća admin ili user iz tokena. Ako je checkSignature true, potpis mora biti isti kao i onaj iz enva
function getRole(token, checkSignature) {
  try {
    const parts = token.split(".");
    if (checkSignature && parts[2] !== hmac(parts[0] + "." + parts[1])) {
      return "user";
    }
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    return payload.role === "admin" ? "admin" : "user";
  } catch (e) {
    return "user";
  }
}

module.exports = { sign, getRole };
