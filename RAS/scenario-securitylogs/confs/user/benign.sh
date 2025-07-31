#!/bin/sh

# Redirect all output to log file
exec > >(tee /log/user/user.log) 2>&1

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target
SESSIONS=3  # Number of concurrent sessions

while [ $# -gt 0 ]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --sessions)
      SESSIONS="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

echo "Enhanced benign user accessing target: $TARGET with $SESSIONS concurrent sessions"
echo "Installing required tools..."

# Install required tools
apk add --no-cache curl jq

echo "Starting enhanced benign user activity..."
echo "Sleeping for 10 seconds before starting benign traffic..."
sleep 10

# User agents for randomization (compatible with Alpine sh)
USER_AGENT_1="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
USER_AGENT_2="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
USER_AGENT_3="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
USER_AGENT_4="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
USER_AGENT_5="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
USER_AGENT_6="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"

# Accept languages (compatible with Alpine sh)
LANG_1="en-US,en;q=0.9"
LANG_2="en-GB,en;q=0.9"
LANG_3="en-CA,en;q=0.9"
LANG_4="de-DE,de;q=0.9,en;q=0.8"
LANG_5="fr-FR,fr;q=0.9,en;q=0.8"
LANG_6="es-ES,es;q=0.9,en;q=0.8"

# Random sleep function
random_sleep() {
    local min=$1
    local max=$2
    local sleep_time=$(($RANDOM % ($max - $min + 1) + $min))
    echo "Sleeping for $sleep_time seconds..."
    sleep $sleep_time
}

# Get random user agent
get_random_ua() {
    local choice=$(($RANDOM % 6 + 1))
    case $choice in
        1) echo "$USER_AGENT_1" ;;
        2) echo "$USER_AGENT_2" ;;
        3) echo "$USER_AGENT_3" ;;
        4) echo "$USER_AGENT_4" ;;
        5) echo "$USER_AGENT_5" ;;
        6) echo "$USER_AGENT_6" ;;
    esac
}

# Get random accept language
get_random_lang() {
    local choice=$(($RANDOM % 6 + 1))
    case $choice in
        1) echo "$LANG_1" ;;
        2) echo "$LANG_2" ;;
        3) echo "$LANG_3" ;;
        4) echo "$LANG_4" ;;
        5) echo "$LANG_5" ;;
        6) echo "$LANG_6" ;;
    esac
}

# Enhanced benign user session function
benign_session() {
    local session_id=$1
    local cookie_file="/tmp/cookies_$session_id.txt"
    local user_agent=$(get_random_ua)
    local accept_lang=$(get_random_lang)
    
    echo "Session $session_id started with UA: $user_agent"
    
    # Common headers
    local headers="-H 'User-Agent: $user_agent' \
                   -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' \
                   -H 'Accept-Language: $accept_lang' \
                   -H 'Accept-Encoding: gzip, deflate' \
                   -H 'Connection: keep-alive' \
                   -H 'Upgrade-Insecure-Requests: 1'"
    
    # 1. Load homepage with static resources
    echo "Session $session_id: Loading homepage with static resources..."
    curl -s -o /dev/null $headers \
         -H 'Referer: -' \
         --cookie-jar "$cookie_file" \
         "$TARGET/"
    
    # Load static resources
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/' \
         --cookie "$cookie_file" \
         "$TARGET/assets/favicon.ico"
    
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/' \
         --cookie "$cookie_file" \
         "$TARGET/assets/css/main.css"
    
    random_sleep 1 3
    
    # 2. Browse products via REST API
    echo "Session $session_id: Browsing products via REST API..."
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/' \
         --cookie "$cookie_file" \
         "$TARGET/rest/products"
    
    random_sleep 2 4
    
    # 3. Search products
    local search_choice=$(($RANDOM % 5 + 1))
    case $search_choice in
        1) local search_term="apple" ;;
        2) local search_term="orange" ;;
        3) local search_term="banana" ;;
        4) local search_term="juice" ;;
        5) local search_term="fruit" ;;
    esac
    echo "Session $session_id: Searching for '$search_term'..."
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/rest/products' \
         --cookie "$cookie_file" \
         "$TARGET/rest/products/search?q=$search_term"
    
    random_sleep 1 3
    
    # 4. Get specific product details
    local product_id=$(($RANDOM % 10 + 1))
    echo "Session $session_id: Viewing product $product_id..."
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/rest/products' \
         --cookie "$cookie_file" \
         "$TARGET/rest/products/$product_id"
    
    random_sleep 2 4
    
    # 5. Attempt login (sometimes with wrong credentials for realism)
    if [ $(($RANDOM % 3)) -eq 0 ]; then
        echo "Session $session_id: Attempting login with wrong credentials..."
        curl -s -o /dev/null $headers \
             -H 'Referer: $TARGET/#/login' \
             -H 'Content-Type: application/json' \
             --cookie "$cookie_file" \
             -X POST \
             -d '{"email":"wrong@example.com","password":"wrongpass"}' \
             "$TARGET/rest/user/login"
    else
        echo "Session $session_id: Attempting login with valid credentials..."
        curl -s -o /dev/null $headers \
             -H 'Referer: $TARGET/#/login' \
             -H 'Content-Type: application/json' \
             --cookie "$cookie_file" \
             -X POST \
             -d '{"email":"admin@juice-sh.op","password":"admin123"}' \
             "$TARGET/rest/user/login"
        
        # If login successful, do authenticated actions
        if [ $? -eq 0 ]; then
            echo "Session $session_id: Login successful, performing authenticated actions..."
            
            # Add item to cart
            echo "Session $session_id: Adding item to cart..."
            curl -s -o /dev/null $headers \
                 -H 'Referer: $TARGET/rest/products' \
                 -H 'Content-Type: application/json' \
                 --cookie "$cookie_file" \
                 -X POST \
                 -d '{"ProductId":1,"quantity":1}' \
                 "$TARGET/rest/cart"
            
            random_sleep 1 2
            
            # View cart
            echo "Session $session_id: Viewing cart..."
            curl -s -o /dev/null $headers \
                 -H 'Referer: $TARGET/rest/products' \
                 --cookie "$cookie_file" \
                 "$TARGET/rest/cart"
            
            random_sleep 1 2
            
            # View user profile
            echo "Session $session_id: Viewing user profile..."
            curl -s -o /dev/null $headers \
                 -H 'Referer: $TARGET/rest/cart' \
                 --cookie "$cookie_file" \
                 "$TARGET/rest/user/whoami"
        fi
    fi
    
    random_sleep 2 4
    
    # 6. Browse frontend routes
    echo "Session $session_id: Browsing frontend routes..."
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/' \
         --cookie "$cookie_file" \
         "$TARGET/#/search"
    
    random_sleep 1 2
    
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/#/search' \
         --cookie "$cookie_file" \
         "$TARGET/#/about"
    
    random_sleep 1 2
    
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/#/about' \
         --cookie "$cookie_file" \
         "$TARGET/#/contact"
    
    random_sleep 1 2
    
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/#/contact' \
         --cookie "$cookie_file" \
         "$TARGET/#/categories"
    
    random_sleep 1 2
    
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/#/categories' \
         --cookie "$cookie_file" \
         "$TARGET/#/basket"
    
    # 7. Introduce some failure scenarios for realism
    if [ $(($RANDOM % 4)) -eq 0 ]; then
        echo "Session $session_id: Accessing non-existent page (404)..."
        curl -s -o /dev/null $headers \
             -H 'Referer: $TARGET/' \
             --cookie "$cookie_file" \
             "$TARGET/nonexistent-page"
    fi
    
    if [ $(($RANDOM % 4)) -eq 0 ]; then
        echo "Session $session_id: Accessing admin panel without permission (403)..."
        curl -s -o /dev/null $headers \
             -H 'Referer: $TARGET/' \
             --cookie "$cookie_file" \
             "$TARGET/#/admin"
    fi
    
    # 8. Logout if logged in
    echo "Session $session_id: Logging out..."
    curl -s -o /dev/null $headers \
         -H 'Referer: $TARGET/#/basket' \
         --cookie "$cookie_file" \
         -X POST \
         "$TARGET/rest/user/logout"
    
    # Clean up cookie file
    rm -f "$cookie_file"
    
    echo "Session $session_id cycle completed"
}

# Main execution loop
while true; do
    echo "Starting new benign user cycle with $SESSIONS concurrent sessions..."
    
    # Start concurrent sessions
    for i in $(seq 1 $SESSIONS); do
        benign_session $i &
    done
    
    # Wait for all sessions to complete
    wait
    
    echo "All sessions completed, waiting before next cycle..."
    random_sleep 15 30
done 