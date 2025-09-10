#!/bin/bash

# Payload Management Script for CyberRange
# Lists, counts, and manages attack payload files

echo "================================"
echo "CyberRange Payload Manager"
echo "================================"

PAYLOAD_DIR="/scripts/attacks"

# Function to count payloads in a file
count_payloads() {
    local file="$1"
    if [[ -f "$file" ]]; then
        grep -v "^#" "$file" | grep -v "^$" | wc -l
    else
        echo "0"
    fi
}

# Function to list category details
list_category() {
    local category="$1"
    local dir="$PAYLOAD_DIR/$category"
    
    if [[ -d "$dir" ]]; then
        echo ""
        echo "📁 Category: $category"
        echo "   Directory: $dir"
        
        local total_payloads=0
        for file in "$dir"/*.txt; do
            if [[ -f "$file" ]]; then
                local count=$(count_payloads "$file")
                total_payloads=$((total_payloads + count))
                echo "   📄 $(basename "$file"): $count payloads"
            fi
        done
        echo "   📊 Total: $total_payloads payloads"
    fi
}

# Function to show sample payloads
show_samples() {
    local category="$1"
    local dir="$PAYLOAD_DIR/$category"
    
    if [[ -d "$dir" ]]; then
        echo ""
        echo "🔍 Sample payloads from $category:"
        for file in "$dir"/*.txt; do
            if [[ -f "$file" ]]; then
                echo "   From $(basename "$file"):"
                grep -v "^#" "$file" | grep -v "^$" | head -2 | while IFS='|' read -r method endpoint payload expected attack_id desc; do
                    echo "     - $desc (ID: $attack_id)"
                done
            fi
        done
    fi
}

# Main menu
case "${1:-list}" in
    list)
        echo ""
        echo "📋 Available Attack Categories:"
        
        # List main payload files
        echo ""
        echo "📄 Main Payload Files:"
        for file in "$PAYLOAD_DIR"/*.txt; do
            if [[ -f "$file" ]]; then
                local count=$(count_payloads "$file")
                echo "   - $(basename "$file"): $count payloads"
            fi
        done
        
        # List category directories
        echo ""
        echo "📁 Category-Specific Payloads:"
        for dir in "$PAYLOAD_DIR"/*/; do
            if [[ -d "$dir" ]]; then
                category=$(basename "$dir")
                list_category "$category"
            fi
        done
        ;;
        
    show)
        category="$2"
        if [[ -z "$category" ]]; then
            echo "Usage: $0 show <category>"
            echo "Available categories:"
            for dir in "$PAYLOAD_DIR"/*/; do
                if [[ -d "$dir" ]]; then
                    echo "   - $(basename "$dir")"
                fi
            done
        else
            list_category "$category"
            show_samples "$category"
        fi
        ;;
        
    count)
        echo ""
        echo "📊 Payload Statistics:"
        
        total=0
        
        # Count main files
        for file in "$PAYLOAD_DIR"/*.txt; do
            if [[ -f "$file" ]]; then
                count=$(count_payloads "$file")
                total=$((total + count))
            fi
        done
        
        # Count category files
        for dir in "$PAYLOAD_DIR"/*/; do
            if [[ -d "$dir" ]]; then
                for file in "$dir"/*.txt; do
                    if [[ -f "$file" ]]; then
                        count=$(count_payloads "$file")
                        total=$((total + count))
                    fi
                done
            fi
        done
        
        echo "   Total attack payloads: $total"
        ;;
        
    test)
        category="${2:-sql_injection}"
        echo ""
        echo "🧪 Testing payload loading for category: $category"
        
        if [[ -d "$PAYLOAD_DIR/$category" ]]; then
            echo "✅ Category directory exists"
            echo "📄 Files found:"
            ls -la "$PAYLOAD_DIR/$category"/*.txt 2>/dev/null
        else
            echo "❌ Category directory not found: $PAYLOAD_DIR/$category"
        fi
        ;;
        
    help|*)
        echo ""
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "   list         List all payload categories and files (default)"
        echo "   show <cat>   Show details for a specific category"
        echo "   count        Count total payloads across all files"
        echo "   test <cat>   Test if category payloads can be loaded"
        echo "   help         Show this help message"
        echo ""
        echo "Examples:"
        echo "   $0 list"
        echo "   $0 show sql_injection"
        echo "   $0 count"
        echo "   $0 test xss"
        ;;
esac

echo ""
echo "================================"
