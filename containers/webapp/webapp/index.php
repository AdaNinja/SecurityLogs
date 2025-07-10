<!DOCTYPE html>
<html>
<head>
    <title>Company Portal - Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #007cba; color: white; padding: 20px; }
        .nav { background: #f5f5f5; padding: 10px; }
        .nav a { margin-right: 20px; text-decoration: none; color: #333; }
        .content { margin: 20px 0; }
        .login-form { max-width: 400px; margin: 20px auto; padding: 20px; border: 1px solid #ccc; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Company Portal</h1>
        <p>Welcome to our secure business portal</p>
    </div>
    
    <div class="nav">
        <a href="/">Home</a>
        <a href="/products.php">Products</a>
        <a href="/about.php">About</a>
        <a href="/contact.php">Contact</a>
        <a href="/login.php">Login</a>
        <a href="/search.php">Search</a>
        <a href="/admin.php">Admin</a>
    </div>
    
    <div class="content">
        <h2>Welcome to Our Company</h2>
        <p>We provide innovative solutions for businesses worldwide.</p>
        
        <div class="login-form">
            <h3>Quick Login</h3>
            <form action="/login.php" method="GET">
                <input type="text" name="user" placeholder="Username" required>
                <input type="password" name="pass" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
        
        <div style="margin-top: 40px;">
            <h3>Recent News</h3>
            <ul>
                <li>New product launch scheduled for next month</li>
                <li>Security updates completed</li>
                <li>Customer satisfaction survey results</li>
            </ul>
        </div>
    </div>
</body>
</html> 