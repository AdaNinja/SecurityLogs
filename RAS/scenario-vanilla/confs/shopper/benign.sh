#!/bin/sh

apk add curl

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

echo "Making benign requests to target: $TARGET"
echo "Sleeping for 60 seconds before starting the benign requests..."
sleep 60

for i in $(seq 1 100); do
  echo "Running benign iteration $i"
  # Simulate a benign request by sending a request to the target
  curl -X GET "$TARGET" -H "User-Agent: Mozilla/5.0 (compatible; BenignBot/1.0)"
done