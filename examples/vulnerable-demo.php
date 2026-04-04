<?php

// ZAFİYETLİ KODLAR (test için)
$id = $_GET['id'];
$name = $_POST['name'];

// SQL Enjeksiyon riski
$query = "SELECT * FROM users WHERE id = " . $id;

// XSS riski
echo $name;

// RCE riski
system("ping " . $_GET['ip']);

// LFI riski
include($_GET['page'] . '.php');

// Güvenli kod (sanitizer)
$safe_id = intval($_GET['id']);
$safe_name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');

// Bu güvenli olmalı, alarm vermemeli
echo $safe_name;
$safe_query = "SELECT * FROM users WHERE id = " . $safe_id;
