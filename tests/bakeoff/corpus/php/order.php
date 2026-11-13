<?php
$db = mysqli_connect("localhost", "app", getenv("DB_PASS"), "app");
$id = (int) $_GET['id'];
$result = mysqli_query($db, "SELECT * FROM orders WHERE id = " . $id);
$order = mysqli_fetch_assoc($result);
echo json_encode($order);
