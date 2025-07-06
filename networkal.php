<?php
// تنظیمات دیتابیس
$host = 'entrance';
$dbname = 'magical_chatterjee';
$username = 'root';
$password = 'Xdww50ATJ7moN7aL0mCZEWvP';

// اتصال به دیتابیس
$mysqli = new mysqli($host, $username, $password, $dbname);
if ($mysqli->connect_error) {
    http_response_code(500);
    echo json_encode(['status'=>'error', 'message'=>'Database connection failed']);
    exit;
}

// کلید رمزنگاری
define('ENCRYPTION_KEY', 'Xdww50ATJ7moN7aL0mCZEWvP');

// تابع رمزنگاری AES-256-CBC
function encryptMessage($plaintext) {
    $key = hash('sha256', ENCRYPTION_KEY, true);
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $role = $_POST['role'] ?? '';
    $message = $_POST['message'] ?? '';

    if (!empty($role) && !empty($message) && in_array($role, ['user', 'ai'])) {
        $encryptedMsg = encryptMessage($message);
        $stmt = $mysqli->prepare("INSERT INTO chats (role, message) VALUES (?, ?)");
        $stmt->bind_param("ss", $role, $encryptedMsg);
        if ($stmt->execute()) {
            echo json_encode(['status'=>'success']);
        } else {
            http_response_code(500);
            echo json_encode(['status'=>'error', 'message'=>'Database insert failed']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['status'=>'error', 'message'=>'Invalid input']);
    }
    exit;
}
?>
