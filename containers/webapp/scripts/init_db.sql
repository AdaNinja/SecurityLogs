-- Initialize vulnerable database for SQLite
-- Create users table with vulnerable data
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create products table
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(50),
    stock INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert vulnerable user data
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@company.com', 'admin'),
('user1', 'password1', 'user1@company.com', 'user'),
('test', 'test123', 'test@company.com', 'user'),
('john', 'john123', 'john@company.com', 'user'),
('alice', 'alice123', 'alice@company.com', 'user'),
('bob', 'bob123', 'bob@company.com', 'user'),
('manager', 'manager123', 'manager@company.com', 'manager'),
('guest', 'guest123', 'guest@company.com', 'guest');

-- Insert product data
INSERT INTO products (name, description, price, category, stock) VALUES
('Laptop Pro', 'High-performance laptop for professionals', 1299.99, 'Electronics', 50),
('Smartphone X', 'Latest smartphone with advanced features', 899.99, 'Electronics', 100),
('Wireless Headphones', 'Noise-cancelling wireless headphones', 299.99, 'Audio', 75),
('Gaming Mouse', 'High-precision gaming mouse', 89.99, 'Gaming', 200),
('USB Drive', '32GB USB flash drive', 19.99, 'Storage', 500),
('Webcam HD', '1080p HD webcam for video calls', 79.99, 'Electronics', 150),
('Keyboard Mechanical', 'Mechanical gaming keyboard', 149.99, 'Gaming', 80),
('Monitor 27"', '27-inch 4K monitor', 399.99, 'Electronics', 30),
('Tablet Pro', 'Professional tablet for work', 599.99, 'Electronics', 60),
('Speaker System', '5.1 surround sound speaker system', 199.99, 'Audio', 40);

-- Create additional tables for more attack vectors
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    total_price DECIMAL(10,2),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    comment TEXT,
    rating INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Insert some sample orders and comments
INSERT INTO orders (user_id, product_id, quantity, total_price) VALUES
(1, 1, 1, 1299.99),
(2, 3, 2, 599.98),
(3, 5, 5, 99.95);

INSERT INTO comments (user_id, product_id, comment, rating) VALUES
(1, 1, 'Great laptop, very fast!', 5),
(2, 3, 'Excellent sound quality', 4),
(3, 5, 'Good value for money', 4);