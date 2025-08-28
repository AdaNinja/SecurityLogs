#!/bin/sh

# Create logs directory structure if it doesn't exist (in container volume)
mkdir -p /logs

# Redirect all output to log file with correct path (in container volume)
exec > >(tee /logs/user.log) 2>&1

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target
DURATION=5  # Default duration in minutes
BEHAVIOR="browse"  # Behavior type (browse, shop, search, login, register, api, mixed)
FREQUENCY="normal"  # Frequency level: low, normal, high
INTERVAL=5  # Interval between actions in seconds
PAGES=10  # Number of pages to browse
KEYWORDS="juice,fruit,organic"  # Search keywords

while [ $# -gt 0 ]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --behavior)
      BEHAVIOR="$2"
      shift 2
      ;;
    --frequency)
      FREQUENCY="$2"
      shift 2
      ;;
    --interval)
      INTERVAL="$2"
      shift 2
      ;;
    --pages)
      PAGES="$2"
      shift 2
      ;;
    --keywords)
      KEYWORDS="$2"
      shift 2
      ;;
    --help)
      echo "Benign User Activity Simulator"
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --target URL       Target URL (default: http://fancystore.com)"
      echo "  --behavior TYPE    Behavior type: browse, shop, search, login, register, api, mixed"
      echo "  --frequency LEVEL  Frequency level: low, normal, high"
      echo "  --interval SEC     Interval between actions in seconds"
      echo "  --pages NUM        Number of pages to browse"
      echo "  --keywords LIST    Comma-separated search keywords"
      echo "  --help             Show this help"
      exit 0
      ;;
    *)
      echo "Unknown option $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

echo "Starting enhanced benign user activity simulation"
echo "Target: $TARGET"
echo "Duration: $DURATION minutes"
echo "Frequency: $FREQUENCY"

# Get container IP for log correlation
CONTAINER_IP=$(hostname -i | awk '{print $1}')
echo "[INFO] Container IP: $CONTAINER_IP"

# Check if Python 3 is available
if command -v python3 >/dev/null 2>&1; then
    echo "Using Python 3 for enhanced benign user simulation"
    
    # Create a temporary Python script
    cat > /tmp/benign_simulator.py << 'EOF'
import time
import random
import urllib.request
import urllib.parse
import urllib.error
import socket
import logging
import sys
import os
import json
from datetime import datetime, timedelta

# Set random seed for reproducibility
random_seed = int(os.environ.get('RANDOM_SEED', 12345))
random.seed(random_seed)
print(f"Benign user simulator using random seed: {random_seed}")

# Setup logging with correct path (in container volume)
log_path = '/logs/user.log'
os.makedirs(os.path.dirname(log_path), exist_ok=True)

# Custom JSON logger
class JSONLogger:
    def __init__(self, log_file):
        self.log_file = log_file
    
    def info(self, message_or_dict):
        self._log('INFO', message_or_dict)
    
    def warning(self, message_or_dict):
        self._log('WARNING', message_or_dict)
    
    def error(self, message_or_dict):
        self._log('ERROR', message_or_dict)
    
    def _log(self, level, message_or_dict):
        if isinstance(message_or_dict, dict):
            log_entry = message_or_dict
        else:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'level': level,
                'message': message_or_dict,
                'source': 'benign_user'
            }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

# Use JSON logger instead of standard logging
logging = JSONLogger(log_path)

def log_info(message, **kwargs):
    """Helper function to log info messages in JSON format"""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'level': 'INFO',
        'message': message,
        'source': 'benign_user'
    }
    log_entry.update(kwargs)
    logging.info(log_entry)

def log_warning(message, **kwargs):
    """Helper function to log warning messages in JSON format"""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'level': 'WARNING',
        'message': message,
        'source': 'benign_user'
    }
    log_entry.update(kwargs)
    logging.warning(log_entry)

def log_error(message, **kwargs):
    """Helper function to log error messages in JSON format"""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'level': 'ERROR',
        'message': message,
        'source': 'benign_user'
    }
    log_entry.update(kwargs)
    logging.error(log_entry)

class BenignUserSimulator:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session_id = f'session_{random.randint(1000, 9999)}'
        self.user_id = f'user_{random.randint(100, 999)}'
        self.container_ip = '172.16.218.130'  # Default fallback
        
        # User behavior patterns
        self.products = [
            'laptop', 'smartphone', 'headphones', 'tablet', 'camera',
            'watch', 'speaker', 'keyboard', 'mouse', 'monitor'
        ]
        
        self.categories = [
            'electronics', 'computers', 'mobile', 'accessories', 'home'
        ]
        
        self.search_terms = [
            'gaming', 'wireless', 'bluetooth', 'portable', 'cheap',
            'premium', 'fast', 'lightweight', 'durable', 'modern'
        ]
        
        # Get search keywords from environment if available
        env_keywords = os.environ.get('BENIGN_KEYWORDS', '')
        if env_keywords:
            self.search_terms.extend(env_keywords.split(','))
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        
        log_info(f'Starting benign user simulation for user {self.user_id}')
        log_info(f'Target URL: {self.target_url}')
        log_info(f'Container IP: {self.container_ip}')
    
    def _make_request(self, method, path, data=None, headers=None):
        """Make HTTP request with proper logging"""
        url = f'{self.target_url}{path}'
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Check if target is reachable (quick DNS check)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            # Special handling for common hostnames
            if parsed.hostname in ['localhost', 'fancystore.com', 'juice-shop']:
                # Skip DNS check for known local hosts
                pass
            else:
                socket.gethostbyname(parsed.hostname)
        except Exception as e:
            log_warning(f'DNS resolution failed for {parsed.hostname}: {e}')
            # Continue anyway for local testing
            pass
        
        if headers is None:
            headers = {}
        
        # Add standard headers
        headers.update({
            'User-Agent': random.choice(self.user_agents),
            'X-Timestamp': timestamp,
            'X-Source-IP': self.container_ip,
            'X-Traffic-Type': 'benign',
            'X-Session-ID': self.session_id,
            'X-User-ID': self.user_id,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        try:
            if method == 'GET':
                req = urllib.request.Request(url, headers=headers)
            else:
                if data:
                    data_bytes = urllib.parse.urlencode(data).encode('utf-8')
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                else:
                    data_bytes = b''
                req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
            
            with urllib.request.urlopen(req, timeout=3) as response:
                status_code = response.getcode()
                
                # Log with detailed information in JSON format
                log_entry = {
                    'timestamp': timestamp,
                    'level': 'INFO',
                    'message': f'SUCCESS {method} {path} - Status: {status_code}',
                    'method': method,
                    'path': path,
                    'status_code': str(status_code),
                    'user_agent': headers.get('User-Agent', ''),
                    'ip': self.container_ip,
                    'session_id': self.session_id,
                    'user_id': self.user_id,
                    'traffic_type': 'benign'
                }
                
                log_info(f'SUCCESS {method} {path} - Status: {status_code}', 
                        method=method, path=path, status_code=str(status_code),
                        user_agent=headers.get('User-Agent', ''), ip=self.container_ip,
                        session_id=self.session_id, user_id=self.user_id, traffic_type='benign')
                return status_code
                
        except urllib.error.HTTPError as e:
            log_warning(f'WARNING {method} {path} - Status: {e.code}',
                       method=method, path=path, status_code=str(e.code),
                       user_agent=headers.get('User-Agent', ''), ip=self.container_ip,
                       session_id=self.session_id, user_id=self.user_id, traffic_type='benign')
            return e.code
        except Exception as e:
            log_error(f'ERROR {method} {path} - Error: {str(e)}',
                     method=method, path=path, status_code='0',
                     user_agent=headers.get('User-Agent', ''), ip=self.container_ip,
                     session_id=self.session_id, user_id=self.user_id, traffic_type='benign')
            return 0
    
    def browse_homepage(self):
        """Browse homepage"""
        log_info('Browsing homepage')
        self._make_request('GET', '/')
        time.sleep(random.uniform(1, 3))
    
    def search_products(self):
        """Search for products"""
        search_term = random.choice(self.search_terms)
        log_info(f'Searching for: {search_term}')
        
        search_data = {
            'q': search_term,
            'category': random.choice(self.categories)
        }
        
        self._make_request('GET', f'/search?{urllib.parse.urlencode(search_data)}')
        time.sleep(random.uniform(2, 4))
    
    def browse_category(self):
        """Browse product category"""
        category = random.choice(self.categories)
        log_info(f'Browsing category: {category}')
        
        self._make_request('GET', f'/category/{category}')
        time.sleep(random.uniform(1, 3))
    
    def view_product(self):
        """View product details"""
        product = random.choice(self.products)
        product_id = random.randint(1, 100)
        log_info(f'Viewing product: {product} (ID: {product_id})')
        
        self._make_request('GET', f'/product/{product_id}')
        time.sleep(random.uniform(2, 5))
    
    def add_to_cart(self):
        """Add product to cart"""
        product_id = random.randint(1, 100)
        quantity = random.randint(1, 3)
        log_info(f'Adding product {product_id} to cart (quantity: {quantity})')
        
        # Track cart items for session consistency
        if not hasattr(self, 'cart_items'):
            self.cart_items = []
        self.cart_items.append(product_id)
        
        cart_data = {
            'product_id': product_id,
            'quantity': quantity,
            'action': 'add'
        }
        
        self._make_request('POST', '/cart', data=cart_data)
        time.sleep(random.uniform(1, 2))
    
    def view_cart(self):
        """View shopping cart"""
        log_info('Viewing shopping cart')
        self._make_request('GET', '/cart')
        time.sleep(random.uniform(1, 2))
    
    def remove_from_cart(self):
        """Remove product from cart"""
        product_id = random.randint(1, 100)
        log_info(f'Removing product {product_id} from cart')
        
        cart_data = {
            'product_id': product_id,
            'action': 'remove'
        }
        
        self._make_request('POST', '/cart', data=cart_data)
        time.sleep(random.uniform(1, 2))
    
    def user_login(self):
        """User login attempt"""
        log_info('Attempting user login')
        
        login_data = {
            'email': f'user{random.randint(1, 100)}@example.com',
            'password': 'password123',
            'remember': 'true'
        }
        
        self._make_request('POST', '/login', data=login_data)
        time.sleep(random.uniform(1, 2))
    
    def user_register(self):
        """User registration attempt"""
        log_info('Attempting user registration')
        
        register_data = {
            'name': f'User{random.randint(1, 100)}',
            'email': f'newuser{random.randint(1, 1000)}@example.com',
            'password': 'securepassword123',
            'confirm_password': 'securepassword123'
        }
        
        self._make_request('POST', '/register', data=register_data)
        time.sleep(random.uniform(1, 2))
    
    def contact_form(self):
        """Submit contact form"""
        log_info('Submitting contact form')
        
        contact_data = {
            'name': f'Contact{random.randint(1, 100)}',
            'email': f'contact{random.randint(1, 100)}@example.com',
            'subject': 'General Inquiry',
            'message': 'I have a question about your products.'
        }
        
        self._make_request('POST', '/contact', data=contact_data)
        time.sleep(random.uniform(1, 2))
    
    def api_call(self):
        """Make API call"""
        api_endpoints = [
            '/api/products',
            '/api/categories', 
            '/api/reviews',
            '/api/featured'
        ]
        
        endpoint = random.choice(api_endpoints)
        log_info(f'Making API call: {endpoint}')
        
        self._make_request('GET', endpoint)
        time.sleep(random.uniform(1, 2))
    
    def run_simulation(self, duration_minutes):
        """Run the complete benign user simulation"""
        log_info(f'Starting benign user simulation for {duration_minutes} minutes')
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        activities = [
            self.browse_homepage,
            self.search_products,
            self.browse_category,
            self.view_product,
            self.add_to_cart,
            self.view_cart,
            self.remove_from_cart,
            self.user_login,
            self.user_register,
            self.contact_form,
            self.api_call
        ]
        
        while datetime.now() < end_time:
            # Choose random activity
            activity = random.choice(activities)
            activity()
            
            # Random delay between activities
            time.sleep(random.uniform(2, 8))
        
        log_info('Benign user simulation completed')
    
    def execute_single_action(self, behavior='browse'):
        """Execute a single benign action for scheduled traffic"""
        log_info(f'Executing single {behavior} action')
        
        # Select action based on behavior
        if behavior == 'browse':
            actions = [self.browse_homepage, self.view_product, self.browse_category]
        elif behavior == 'shop' or behavior == 'shopping':
            actions = [self.add_to_cart, self.view_cart, self.view_product, self.browse_category]
        elif behavior == 'search':
            actions = [self.search_products, self.browse_category]
        elif behavior == 'login':
            actions = [self.user_login]
        elif behavior == 'register':
            actions = [self.user_register]
        elif behavior == 'api':
            actions = [self.api_call]
        elif behavior == 'mixed':
            # Use all available actions for mixed behavior
            actions = [
                self.browse_homepage, self.search_products, self.browse_category,
                self.view_product, self.add_to_cart, self.view_cart,
                self.user_login, self.api_call
            ]
        else:
            # Default to browsing
            actions = [self.browse_homepage, self.search_products]
        
        # Execute one random action
        action = random.choice(actions)
        try:
            action()
            log_info(f'Single {behavior} action completed successfully')
        except Exception as e:
            log_warning(f'Single action failed: {str(e)}')

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://fancystore.com'
    behavior = sys.argv[2] if len(sys.argv) > 2 else 'browse'
    frequency = sys.argv[3] if len(sys.argv) > 3 else 'normal'
    
    # Create simulator
    simulator = BenignUserSimulator(target)
    
    # Adjust timing based on frequency
    frequency_multipliers = {
        'low': 0.5,      # 50% slower (longer delays)
        'normal': 1.0,   # Normal speed
        'high': 2.0      # 2x faster (shorter delays)
    }
    multiplier = frequency_multipliers.get(frequency, 1.0)
    
    # Always execute single action for scheduled traffic
    log_info(f'Single action mode: target={target}, behavior={behavior}, frequency={frequency} (multiplier={multiplier})')
    simulator.execute_single_action(behavior)
EOF

    # Export environment variables for Python script
    export BENIGN_INTERVAL="$INTERVAL"
    export BENIGN_PAGES="$PAGES"
    export BENIGN_KEYWORDS="$KEYWORDS"
    
    # Run the Python script with proper arguments
    python3 /tmp/benign_simulator.py "$TARGET" "$BEHAVIOR" "$FREQUENCY"
    
    # Clean up
    rm -f /tmp/benign_simulator.py
    
else
    echo "Python 3 not available, using fallback method"
    
    # Fallback to basic curl/wget if Python is not available
    if command -v curl >/dev/null 2>&1; then
        HTTP_CLIENT="curl"
    elif command -v wget >/dev/null 2>&1; then
        HTTP_CLIENT="wget"
    else
        echo "No HTTP client available, using echo simulation"
        HTTP_CLIENT="echo"
    fi
    
    echo "Using HTTP client: $HTTP_CLIENT"
    
    # Calculate iterations based on duration (1 request every 2 seconds)
    ITERATIONS=$((DURATION * 30))  # 30 requests per minute
    
    for i in $(seq 1 $ITERATIONS); do
        echo "Running benign iteration $i of $ITERATIONS"
        TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        
        case $HTTP_CLIENT in
            curl)
                curl -X GET "$TARGET" \
                    -H "User-Agent: Mozilla/5.0 (compatible; BenignBot/1.0)" \
                    -H "X-Timestamp: $TIMESTAMP" \
                    -H "X-Source-IP: $CONTAINER_IP" \
                    -H "X-Traffic-Type: benign" \
                    -s -o /dev/null -w "%{http_code}"
                ;;
            wget)
                wget -q --header="User-Agent: Mozilla/5.0 (compatible; BenignBot/1.0)" \
                     --header="X-Timestamp: $TIMESTAMP" \
                     --header="X-Source-IP: $CONTAINER_IP" \
                     --header="X-Traffic-Type: benign" \
                     -O /dev/null "$TARGET" 2>/dev/null && echo "200" || echo "000"
                ;;
            echo)
                echo "Simulated benign request $i to $TARGET at $TIMESTAMP"
                ;;
        esac
        
        sleep 2
    done
fi

echo "Benign traffic simulation completed" 