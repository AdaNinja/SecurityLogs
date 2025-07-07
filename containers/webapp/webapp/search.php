<?php
// Real vulnerable search page with SQL injection
session_start();

// Database connection
$host = 'localhost';
$dbname = 'vulnerable_db';
$username = 'webapp';
$password = 'webapp_password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

$results = [];
$search_term = '';

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['q'])) {
    $search_term = $_GET['q'];
    
    // VULNERABLE: SQL injection in search
    $sql = "SELECT * FROM products WHERE name LIKE '%$search_term%' OR description LIKE '%$search_term%'";
    
    try {
        $stmt = $pdo->query($sql);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch(PDOException $e) {
        $error = "Search error: " . $e->getMessage();
    }
}

// Log search attempts
$log_entry = date('Y-m-d H:i:s') . " - Search: " . $search_term . " from " . $_SERVER['REMOTE_ADDR'] . "\n";
file_put_contents('/var/log/search_attempts.log', $log_entry, FILE_APPEND);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Search - Company Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #007cba; color: white; padding: 20px; }
        .nav { background: #f5f5f5; padding: 10px; }
        .nav a { margin-right: 20px; text-decoration: none; color: #333; }
        .content { margin: 20px 0; }
        .search-form { max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ccc; }
        input[type="text"] { width: 70%; padding: 10px; margin: 10px 0; }
        button { padding: 10px 20px; background: #007cba; color: white; border: none; cursor: pointer; }
        .results { margin-top: 20px; }
        .product { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
        .product h3 { margin-top: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Company Portal - Search</h1>
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
        <div class="search-form">
            <h2>Search Products</h2>
            <form method="GET" action="/search.php">
                <input type="text" name="q" placeholder="Enter search term..." 
                       value="<?php echo htmlspecialchars($search_term); ?>" required>
                <button type="submit">Search</button>
            </form>
        </div>
        
        <?php if (!empty($search_term)): ?>
            <div class="results">
                <h3>Search Results for: "<?php echo htmlspecialchars($search_term); ?>"</h3>
                <p>Found <?php echo count($results); ?> results</p>
                
                <?php if (empty($results)): ?>
                    <p>No products found matching your search criteria.</p>
                <?php else: ?>
                    <?php foreach ($results as $product): ?>
                        <div class="product">
                            <h3><?php echo htmlspecialchars($product['name']); ?></h3>
                            <p><strong>Price:</strong> $<?php echo htmlspecialchars($product['price']); ?></p>
                            <p><?php echo htmlspecialchars($product['description']); ?></p>
                            <p><strong>Category:</strong> <?php echo htmlspecialchars($product['category']); ?></p>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html> 