<?php
$db = mysqli_connect("localhost", "app", getenv("DB_PASS"), "app");
$result = mysqli_query($db, "SELECT * FROM users WHERE email = '" . $_GET['email'] . "'");
while ($row = mysqli_fetch_assoc($result)) {
    echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
}
