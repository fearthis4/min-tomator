#!/bin/bash

# Initialize variables with default values
mode=""
root_path=""
output_file=""
target_manifest=""
source_directory=""

# Function to display the script usage
function display_usage {
    echo "Usage: $0 -m <mode> -r <root_path> [-o <output_file>] [-t <target_manifest> -s <source_directory>]"
    echo "Options:"
    echo "  -m : Mode of operation ('create' or 'install')"
    echo "  -r : Root path to traverse or update"
    echo "  -o : Output file for manifest creation (required for 'create')"
    echo "  -t : Target manifest file for installation (required for 'install')"
    echo "  -s : Source directory for file copy (required for 'install')"
}

# Parse the command-line options
while getopts "m:r:o:t:s:" opt; do
    case $opt in
        m)
            mode="$OPTARG"
            ;;
        r)
            root_path="$OPTARG"
            ;;
        o)
            output_file="$OPTARG"
            ;;
        t)
            target_manifest="$OPTARG"
            ;;
        s)
            source_directory="$OPTARG"
            ;;
        \?)
            display_usage
            exit 1
            ;;
    esac
done

# Check if the required options are provided
if [[ -z $mode || -z $root_path ]]; then
    display_usage
    exit 1
fi

# Function to recursively traverse the directory structure and write file paths to the manifest
function traverse_directory {
    local dir_path=$1
    local root_length=${#root_path}

    # Loop through files and directories in the current directory
    for file in "$dir_path"/*; do
        # Check if the path is a directory
        if [ -d "$file" ]; then
            # Recursively call the function for subdirectories
            traverse_directory "$file"
        else
            # Get the relative file path
            file_path=${file:$root_length}

            # Exclude the root directory from manifest
            if [[ "$file_path" != "/" ]]; then
                # Write the file path to the manifest
                echo "$file_path" >> "$output_file"
            fi
        fi
    done
}

# Check the mode
if [ "$mode" == "create" ]; then
    # Check required variable is provided
    if [[ -z $output_file ]]; then
        display_usage
        exit 1
    fi
    # Create or overwrite the output file
    > "$output_file"

    # Create a manifest file from the root path
    traverse_directory "$root_path"
    echo "Manifest file created successfully."
elif [ "$mode" == "install" ]; then
    # Check required variable is provided
    if [[ -z $target_manifest || -z $source_directory ]]; then
        display_usage
        exit 1
    fi
    # Check if the target manifest file exists
    if [ ! -f "$target_manifest" ]; then
        echo "Target manifest file not found."
        exit 1
    fi

    # Read the file paths from the target manifest
    target_files=$(cat "$target_manifest")

    # Loop through each file path in the target manifest
    while IFS= read -r target_file; do
        # Construct the source and destination paths
        source_path="${source_directory}/${target_file}"
        destination_path="${root_path}/${target_file}"

        # Check if the file exists in the root path
        if [ ! -e "$destination_path" ]; then
            # Output Command To Create the parent directories if they don't exist
            echo "mkdir -p \"$(dirname $destination_path)\""

            # Output the command to copy the file
            echo "cp -p \"$source_path\" \"$destination_path\""
        else
            # Compare the source and destination files
            if ! cmp -s "$source_path" "$destination_path"; then
                # Output the command to update the file
                echo "cp -p \"$source_path\" \"$destination_path\""
            else
                echo "# File: '$destination_path' already matches the source, nothing to do..."
            fi
        fi
    done <<< "$target_files"

    echo "# Target root path updated to match the manifest."
else
    display_usage
    exit 1
fi
