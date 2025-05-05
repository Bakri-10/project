#!/bin/bash
# Test script to verify the functionality of the server compliance email notification system

echo "Starting test..."

# Create necessary directories
mkdir -p output
mkdir -p temp

# Test the email generation using the mock data
echo "Testing email generation..."
python3 test_email_generation.py --input-dir . --output-dir ./output

# Check if the email file was created
if [ -f "./output/ATU0_email.txt" ]; then
    echo "Email generation successful!"
    echo "Email content:"
    echo "----------------------------------------"
    cat "./output/ATU0_email.txt"
    echo "----------------------------------------"
else
    echo "Failed to generate email content."
    exit 1
fi

# Display CSV files if they exist
for csv_file in ./output/*.csv; do
    if [ -f "$csv_file" ]; then
        echo "Generated CSV file: $csv_file"
        echo "First few lines:"
        head -n 5 "$csv_file"
        echo "----------------------------------------"
    fi
done

echo "Test completed successfully!" 