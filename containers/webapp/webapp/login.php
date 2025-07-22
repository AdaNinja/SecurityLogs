<?php
// Real vulnerable login page with SQL injection
session_start();

// Database connection (vulnerable) - SQLite
$db_path = '/var/www/html/database.sqlite';

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

$error = '';
$success = '';

// Process login form
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['user']) && isset($_GET['pass'])) {
    $user = $_GET['user'];
    $pass = $_GET['pass'];
    
    // VULNERABLE: Direct SQL injection possible
    $sql = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    
    try {
        $stmt = $pdo->query($sql);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($result) {
            $success = "Login successful! Welcome " . htmlspecialchars($result['username']);
            $_SESSION['user_id'] = $result['id'];
            $_SESSION['username'] = $result['username'];
        } else {
            $error = "Invalid username or password";
        }
    } catch(PDOException $e) {
        $error = "Database error: " . $e->getMessage();
    }
}

// Log access attempt
$log_entry = date('Y-m-d H:i:s') . " - Login attempt: " . 
             (isset($_GET['user']) ? $_GET['user'] : 'none') . 
             " from " . $_SERVER['REMOTE_ADDR'] . "\n";
file_put_contents('/var/log/logs/login_attempts.log', $log_entry, FILE_APPEND);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login - Company Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #007cba; color: white; padding: 20px; }
        .nav { background: #f5f5f5; padding: 10px; }
        .nav a { margin-right: 20px; text-decoration: none; color: #333; }
        .content { margin: 20px 0; }
        .login-form { max-width: 400px; margin: 20px auto; padding: 20px; border: 1px solid #ccc; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; cursor: pointer; }
        .error { color: red; background: #ffe6e6; padding: 10px; margin: 10px 0; }
        .success { color: green; background: #e6ffe6; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Company Portal - Login</h1>
    </div>
    
    <div class="nav">
        <a href="/">Home</a>
        <a href="/products.php">Products</a>
        <a href="/about.php">About</a>
        <a href="/contact.php">Contact</a>
        <a href="/login.php">Login</a>
        <a href="/search.php">Search</a>
    </div>
    
    <div class="content">
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        
        <div class="login-form">
            <h2>User Login</h2>
            <form method="GET" action="/login.php">
                <input type="text" name="user" placeholder="Username" required 
                       value="<?php echo isset($_GET['user']) ? htmlspecialchars($_GET['user']) : ''; ?>">
                <input type="password" name="pass" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            
            <div style="margin-top: 20px; font-size: 12px; color: #666;">
                <p>Demo accounts:</p>
                <ul>
                    <li>admin / admin123</li>
                    <li>user1 / password1</li>
                    <li>test / test123</li>
                </ul>
            </div>
        </div>
        
        <div style="margin-top: 40px;">
            <h3>Security Notice</h3>
            <p>This is a demonstration environment for security testing purposes only.</p>
        </div>
    </div>
</body>
</html> 