<?php
$dir = $_GET['dir'] ?? '.';
system("ls -l " . escapeshellarg($dir));
