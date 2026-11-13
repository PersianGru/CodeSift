// Deliberately vulnerable sample for CodeSift tests. Never deploy.
const express = require("express");
const { exec } = require("child_process");
const _ = require("lodash");

const app = express();

app.get("/run", (req, res) => {
  // REAL: command injection
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  // REAL: eval of user input
  res.send(String(eval(req.query.expr)));
});

app.get("/hello", (req, res) => {
  // REAL: reflected XSS
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.get("/merge", (req, res) => {
  // REAL: prototype pollution sink with user JSON
  res.json(_.merge({}, JSON.parse(req.query.data)));
});

app.get("/version", (req, res) => {
  // FALSE POSITIVE: constant command, no user input
  exec("node --version", (err, out) => res.send(out));
});

app.listen(3000);
