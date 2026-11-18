// Deliberately vulnerable toy Express app used as a SAST fixture. DO NOT DEPLOY.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());
const BASE = "/srv/files";

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out)); // PLANT: command injection
});

app.get("/calc", (req, res) => {
  const result = eval(req.query.expr); // PLANT: code injection
  res.send(String(result));
});

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key]; // PLANT: prototype pollution
    }
  }
  return target;
}

app.post("/settings", (req, res) => {
  const settings = merge({}, req.body);
  res.json(settings);
});

app.get("/go", (req, res) => {
  res.redirect(req.query.url); // PLANT: open redirect
});

app.get("/file", (req, res) => {
  const p = path.join(BASE, req.query.name);
  res.send(fs.readFileSync(p, "utf8")); // PLANT: path traversal
});

app.listen(3000);
module.exports = { merge };
