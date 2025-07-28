#!/bin/sh

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target

while [ $# -gt 0 ]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

echo "Benign user accessing target: $TARGET"
echo "Installing required tools..."

# Install curl for benign requests
apk add --no-cache curl

echo "Starting benign user activity..."
echo "Sleeping for 10 seconds before starting benign traffic..."
sleep 10

# Simulate benign user behavior
while true; do
    echo "Benign user: Browsing homepage..."
    curl -s -o /dev/null "$TARGET/"
    sleep 2
    
    echo "Benign user: Checking products..."
    curl -s -o /dev/null "$TARGET/#/search"
    sleep 3
    
    echo "Benign user: Viewing about page..."
    curl -s -o /dev/null "$TARGET/#/about"
    sleep 2
    
    echo "Benign user: Checking contact page..."
    curl -s -o /dev/null "$TARGET/#/contact"
    sleep 4
    
    echo "Benign user: Browsing categories..."
    curl -s -o /dev/null "$TARGET/#/categories"
    sleep 3
    
    echo "Benign user: Checking basket..."
    curl -s -o /dev/null "$TARGET/#/basket"
    sleep 2
    
    echo "Benign user cycle completed, waiting 10 seconds..."
    sleep 10
done 