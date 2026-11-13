const express = require("express");
const escapeHtml = require("escape-html");

const app = express();

app.get("/search", (req, res) => {
  res.send("<p>Results for " + escapeHtml(req.query.q) + "</p>");
});

module.exports = app;
