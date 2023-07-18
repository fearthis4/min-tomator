#!/bin/bash

# Set default values for variables
DEFAULT_ROOT_PATH="/path/to/project"
DEFAULT_MANIFEST_FILE="manifest.txt"
DEFAULT_INSTALL_DIR="/path/to/installation/directory"
DEFAULT_SOURCE_DIRECTORY="/path/to/source/directory"
DEFAULT_SERVICE_NAME="min-tomator"

service_file_template=$(cat <<EOF
[Unit]
Description=My Python Service
After=network.target

[Service]
User=$USER
WorkingDirectory=$install_dir
ExecStart=$install_dir/venv/bin/python $install_dir/script.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
)

# Function to display an error message and exit
function display_error {
    echo "Error: $1"
    exit 1
}

# Function to display the script usage
function display_usage {
    echo "Usage: $0 -r <root_path> -m <manifest_file> -d <install_dir> [-n <service_name>] [-s <source_directory>]"
    echo "Options:"
    echo "  -r : Root path to traverse or update (default: $DEFAULT_ROOT_PATH)"
    echo "  -m : Manifest file (required)"
    echo "  -d : Installation directory (default: $DEFAULT_INSTALL_DIR)"
    echo "  -n : Service name (default: $DEFAULT_SERVICE_NAME)"
    echo "  -s : Source directory for files to be installed (default: $DEFAULT_SOURCE_DIRECTORY)"
    exit 1
}

# Function to install the manifest and update the root path
function install_manifest {
    local root_path=$1
    local manifest_file=$2
    local source_directory=$3
    bash manifest.sh -m install -r "$root_path" -t "$manifest_file" -s "$source_directory" > update_script.sh
    chmod +x update_script.sh
    ./update_script.sh
}

# Function to create and activate the virtual environment
function create_virtualenv {
    python3 -m venv myenv
    source myenv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    # Run additional setup commands if needed
}

# Function to generate the systemd service unit file
function generate_systemd_service {
    local service_name=$1
    local install_dir=$2
    local service_file="/etc/systemd/system/${service_name}.service"

    cat > "$service_file" <<EOF
[Unit]
Description=Min-Tomator Automation Service
After=network.target

[Service]
User=$USER
WorkingDirectory=$install_dir
ExecStart=$install_dir/venv/bin/python $install_dir/script.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
}

# Function to restart the systemd service
function restart_systemd_service {
    local service_name=$1
    sudo systemctl daemon-reload
    sudo systemctl enable "$service_name"
    sudo systemctl restart "$service_name"
}

# Function to verify the systemd service file
function verify_systemd_service {
    local service_name=$1
    local install_dir=$2
    local service_file="/etc/systemd/system/${service_name}.service"
    local expected_service=$(generate_systemd_service "$service_name" "$install_dir")
    if [ -f "$service_file" ]; then
        diff -q "$service_file" <(echo "$expected_service") >/dev/null
        return $?
    else
        return 1
    fi
}

# Function to verify the virtual environment
function verify_virtualenv {
    local install_dir=$1
    if [ -d "$install_dir/venv" ]; then
        source "$install_dir/venv/bin/activate"
        pip check -r requirements.txt >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            deactivate
            return 0
        else
            deactivate
            return 1
        fi
    else
        return 1
    fi
}

# Function to check if a directory is empty
function is_directory_empty {
    local dir=$1
    if [ -z "$(ls -A "$dir")" ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Parse command-line arguments
while getopts "r:m:d:n:s:" opt; do
    case $opt in
        r)
            root_path=$OPTARG
            ;;
        m)
            manifest_file=$OPTARG
            ;;
        d)
            install_dir=$OPTARG
            ;;
        n)
            service_name=$OPTARG
            ;;
        s)
            source_directory=$OPTARG
            ;;
        \?)
            display_usage
            ;;
    esac
done

# Set variables to default values if not provided
root_path=${root_path:-$DEFAULT_ROOT_PATH}
manifest_file=${manifest_file:-$DEFAULT_MANIFEST_FILE}
install_dir=${install_dir:-$DEFAULT_INSTALL_DIR}
source_directory=${source_directory:-$DEFAULT_SOURCE_DIRECTORY}
service_name=${service_name:-$DEFAULT_SERVICE_NAME}

# Check if the manifest file exists
if [ ! -f "$manifest_file" ]; then
    display_error "Manifest file not found."
    display_usage
fi

# Check if the install directory is provided
if [ -z "$install_dir" ]; then
    display_usage
fi

# Check if the install directory is empty
if [ "$(is_directory_empty "$install_dir")" == "false" ]; then
    echo "Running in update mode..."
    # Install the manifest and update the root path
    install_manifest "$root_path" "$manifest_file" "$source_directory"

    # Check if the service file exists and needs to be updated
    if [ -f "/etc/systemd/system/${service_name}.service" ]; then
        echo "Service file already exists, no need to update."
    else
        echo "Generating service file..."
        generate_systemd_service "$service_name" "$install_dir"
    fi

    # Check if the virtual environment exists and needs to be updated
    if [ -d "$install_dir/venv" ]; then
        echo "Virtual environment already exists, no need to update."
    else
        echo "Creating virtual environment..."
        create_virtualenv
    fi

    # Restart the systemd service
    restart_systemd_service "$service_name"

    echo "Update completed successfully."
    exit 0
fi
# Else run in new install mode
# Install the manifest and update the root path
install_manifest "$root_path" "$manifest_file" "$source_directory"

# Create and activate the virtual environment
create_virtualenv

# Generate the systemd service unit file
generate_systemd_service "$service_name" "$install_dir"

# Restart the systemd service
restart_systemd_service "$service_name"

echo "Installation completed successfully."
