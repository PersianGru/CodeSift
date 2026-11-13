const express = require("express");
const { exec } = require("child_process");

const app = express();

app.get("/version", (req, res) => {
  exec("git rev-parse --short HEAD", (err, stdout) => {
    res.json({ version: stdout.trim() });
  });
});

module.exports = app;
