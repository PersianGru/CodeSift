<?php
// Deliberately vulnerable sample for CodeSift tests. Never deploy.

$db = mysqli_connect("localhost", "app", getenv("DB_PASS"), "app");

// REAL: SQL injection
$result = mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET['id']);

// REAL: reflected XSS
echo "Hello " . $_GET['name'];

// REAL: command injection
system("ping -c 1 " . $_GET['host']);

// REAL: unsafe deserialization
$prefs = unserialize($_COOKIE['prefs']);

// REAL: file inclusion from user input
include($_GET['page'] . ".php");

// FALSE POSITIVE: escaped output
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
