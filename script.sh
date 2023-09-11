#!/bin/bash

#Declare global variables
declare -g deviceId
declare -g dpsIdScope
declare -g iddUrl
declare -g iotPrivateKey
declare -g iotChainCert
declare -g publishCAKey
declare -g localVideoCert

# Check if the script is run with root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or with sudo."
  exit 1
fi

function create_user {
	# Create signwave user
	echo "Creating signwave user..."
	sudo useradd -m -s /bin/bash signwave
	echo 'signwave:Tekcent123@' | sudo chpasswd

	status=$?
	if [ $status -ne 0 ]; then
	echo "Failed to create signwave user. Exiting..."
	sudo userdel signwave
	exit 1
	fi
	# Add admin user to sudo group
	echo "Adding signwave user to sudo group..."
	sudo usermod -aG sudo signwave

	status=$?
	if [ $status -ne 0 ]; then
	echo "Failed to add signwave user to sudo group. Exiting..."
	exit 1
	fi

	# Create kiosk user
	echo "Creating kiosk user..."
	sudo useradd -m -s /bin/bash kiosk
	echo 'kiosk:Kiosk123@' | sudo chpasswd

	status=$?
	if [ $status -ne 0 ]; then
	echo "Failed to create kiosk user. Exiting..."
	sudo userdel kiosk
	exit 1
	fi
}

#EDGE SECTION
#function to install Iot Edge runtime
function installIotEdgeRuntime {
	#INSTALL IOT EDGE
	echo "Download and install Debian package: packages-microsoft-prod.deb..."
	wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
	sudo dpkg -i packages-microsoft-prod.deb
	rm packages-microsoft-prod.deb

	#Install a container engine
	echo "Install a container engine..."
	sudo apt-get update; \
	  sudo apt-get install -y moby-engine
	  
	#Install the IoT Edge runtime
	echo "Install the IoT Edge runtime..."
	sudo apt-get update; \
	   sudo apt-get install -y aziot-edge
}


function configIotEdge {
	echo "Begin config IoT Edge..."
	# Remove file if it exist
	configPath='/etc/aziot/config.toml'
	privateKeyPath='/etc/aziot/iot-device.key.pem'
	fullchainCertPath='/etc/aziot/iot-device-full-chain.cert.pem'
	
	#Save Primary Key to file
	echo -e "$iotPrivateKey" > $privateKeyPath
	
	#Save Device Cert to file
	echo -e "$iotChainCert" > $fullchainCertPath
	
	if [ -f $configPath ] ; then
			sudo rm -f $configPath
	fi
	echo -e "
	[provisioning]
	source = 'dps'
	global_endpoint = 'https://global.azure-devices-provisioning.net/'
	id_scope = '$1'
	[provisioning.attestation]
	method = 'x509'
	registration_id = '$2'
	identity_pk = 'file://$privateKeyPath'
	identity_cert = 'file://$fullchainCertPath'" > $configPath
	# Grand acess to files
	echo "Grand acess right to files /etc/aziot/"
	sudo chmod a+rwx /etc/aziot/config.toml /etc/aziot/iot-device.key.pem /etc/aziot/iot-device-full-chain.cert.pem
	echo "End config IoT Edge"
	sudo iotedge config apply
}

#Function for Install self-cert for local video
function installLocalVideoCert {
	echo "Import self certificate for Local Video Server..."
	localVideoCertPath='localhost.crt'
	if [ -f $localVideoCertPath ] ; then
			sudo rm -f $localVideoCertPath
	fi
	#Save selft-cert for Local video to file
	echo -e "$localVideoCert" > $localVideoCertPath
	
	# Import certificate to machine	
	sudo cp $localVideoCertPath /usr/local/share/ca-certificates/$localVideoCertPath
	sudo update-ca-certificates
}



function install_chromium-browser {
	#install chromium-browser
	echo "Installing chromium-browser..."
	# Install chromium from snap repo
	sudo snap install chromium
	if [ $status -ne 0 ]; then
	echo "Failed to install chromium-browser. Exiting..."
	exit 1
	fi

	# Set chromium as default browser
	xdg-mime default chromium_chromium.desktop text/html
	xdg-mime default chromium_chromium.desktop x-scheme-handler/http
	xdg-mime default chromium_chromium.desktop x-scheme-handler/https
	xdg-mime default chromium_chromium.desktop x-scheme-handler/about
}

function make_api_post_request {
    local url="$1"
    local username="$2"
    local password="$3"
    local data="$4"

    # Set the maximum number of retries
    local max_retries=3

    # Initialize a variable to keep track of the current retry attempt
    local retry_count=0

    # Retry the API call until it's successful or reaches the maximum number of retries
    while [ $retry_count -lt $max_retries ]; do
        # Make the POST request with Basic Authentication and store the response in a variable
        local response=$(curl -s -X POST -H "Content-Type: application/json" -d "$data" -u "$username:$password" "$url")

        # Check if the request was successful
         success=$(echo "$response" | jq -r '.succeeded')
        if [ $? -eq 0 ] && [ "$success" = "true" ]; then
            echo "Request successful. Response:"
            echo "$response"

            # Extract values from the JSON response using jq
			deviceId=$(echo "$response" | jq -r '.data.deviceId')
            dpsIdScope=$(echo "$response" | jq -r '.data.dpsIdScope')
            iddUrl=$(echo "$response" | jq -r '.data.iddUrl')
            iotPrivateKey=$(echo "$response" | jq -r '.data.iotPrivateKey')
            iotChainCert=$(echo "$response" | jq -r '.data.iotChainCert')
            publishCAKey=$(echo "$response" | jq -r '.data.publishCAKey')
            localVideoCert=$(echo "$response" | jq -r '.data.localVideoCert')

            # Print the extracted values
            echo "dpsIdScope: $dpsIdScope"
            echo "iddUrl: $iddUrl"
            echo "IoT Private Key: $iotPrivateKey"
            echo "IoT Chain Certificate: $iotChainCert"
            echo "Publish CA Key: $publishCAKey"
            echo "local video cert: $localVideoCert"

            # Exit the loop if the request was successful
            break
        else
            echo "Request failed. Retrying..."
            ((retry_count++))
        fi

        # Sleep for a few seconds before the next retry (optional)
        sleep 2
    done

    # Check if all retries failed
    if [ $retry_count -eq $max_retries ]; then
		echo "Something wrong. Please check your username and password"
        echo "Maximum number of retries reached. Request could not be completed."
        exit 1
    fi
}

function install_ssh_sever {
    # Install SSH server
    echo "Installing SSH server..."
    sudo apt update
    sudo apt install openssh-server -y

    status=$?
    if [ $status -ne 0 ]; then
        echo "Failed to install SSH server. Exiting..."
        exit 1
    fi

    #Create ca publishkey
    sudo echo -e "$publishCAKey" > /etc/ssh/ca_key.pub
    status=$?
    if [ $status -ne 0 ]; then
        echo "Failed to create ca_key.pub. Exiting..."
        exit 1
    fi

    # Check if the TrustedUserCAKeys line is enabled
    if grep -q 'TrustedUserCAKeys' /etc/ssh/sshd_config; then
        # Remove the commented-out line (if it exists)
        sudo sed -i '/TrustedUserCAKeys/d' /etc/ssh/sshd_config
    fi

    # Append the TrustedUserCAKeys line
    echo 'TrustedUserCAKeys /etc/ssh/ca_key.pub' | sudo tee -a /etc/ssh/sshd_config
	echo 'Match User signwave' | sudo tee -a /etc/ssh/sshd_config
	echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config

    status=$?
    if [ $status -ne 0 ]; then
        echo "Failed to update sshd_config. Exiting..."
        exit 1
    fi

    # Start SSH service
    echo "Starting SSH service..."
    sudo systemctl start ssh

    status=$?
    if [ $status -ne 0 ]; then
        echo "Failed to start SSH service. Exiting..."
        exit 1
    fi

    # Enable SSH service on boot
    echo "Enabling SSH service on boot..."
    sudo systemctl enable ssh

    status=$?
    if [ $status -ne 0 ]; then
        echo "Failed to enable SSH service on boot. Exiting..."
        exit 1
    fi
}

function setup_auto_login {
	# GDM configuration file path
	GDM_CONFIG_FILE="/etc/gdm3/custom.conf"
	# Username for automatic login
	AUTOMATIC_LOGIN_USER="kiosk"
	# Check if the custom.conf file exists
	if [ -f "$GDM_CONFIG_FILE" ]; then
		# Check if the AutomaticLoginEnable line already exists in the custom.conf file
		if ! grep -q "AutomaticLoginEnable=True" "$GDM_CONFIG_FILE"; then
			# Add the necessary lines to enable automatic login
			echo "[daemon]" >> "$GDM_CONFIG_FILE"
			echo "AutomaticLoginEnable=True" >> "$GDM_CONFIG_FILE"
			echo "AutomaticLogin=$AUTOMATIC_LOGIN_USER" >> "$GDM_CONFIG_FILE"
			echo "Automatic login is now enabled for user: $AUTOMATIC_LOGIN_USER"
		else
			echo "Automatic login is already enabled in $GDM_CONFIG_FILE."
		fi
	else
		echo "The $GDM_CONFIG_FILE file does not exist. Please make sure GDM is installed."
	fi
}

function create_kiosk_systemd {
	# Create the service unit file
	SERVICE_FILE="/etc/systemd/system/chromium-kiosk.service"
cat << EOF > $SERVICE_FILE
[Unit]
Description=Chromium Kiosk
After=graphical.target

[Service]
ExecStart=/snap/bin/chromium --start-fullscreen --kiosk --disable-infobars --noerrdialogs --disable-session-crashed-bubble --disable-features=Translate "$iddUrl"
Restart=on-failure
User=kiosk
Environment=DISPLAY=:0

[Install]
WantedBy=default.target
EOF

	status=$?
	if [ $status -ne 0 ]; then
	echo "Failed to created chromium-kiosk service. Exiting..."
	exit 1
	fi

	# Enable the service
	echo "Enabling chromium-kiosk service on boot..."
	systemctl enable chromium-kiosk.service
	status=$?
	if [ $status -ne 0 ]; then
	echo "Failed to enable chromium-kiosk service on boot. Exiting..."
	exit 1
	fi
}

# Prompt the user for a username
read -p "Enter your username: " username

# Prompt the user for a password (hide input)
read -s -p "Enter your password: " password

#Get MAC address
mac_address=$(ip a | awk '/link\/ether/ && $2 != "00:00:00:00:00:00" {print $2; exit}')

#install nesscessary package
sudo apt update -y 
sudo apt install -y curl
sudo apt install -y jq

echo $mac_address

# API endpoint URL
url="http://10.68.1.34:32705/api/Device/register"

# Data to send in the request body
api_data="{
  \"macAddress\": \"$mac_address\"
}"

# Call the function to make the API POST request
make_api_post_request "$url" "$username" "$password" "$api_data"


#Start run script
create_user

install_ssh_sever

#Run function to install Iot Edge runtime
installIotEdgeRuntime

#Run function to config IotEdge
configIotEdge $dpsIdScope $deviceId

#Install self-cert for local video
installLocalVideoCert
#END EDGE SECTION

install_chromium-browser

create_kiosk_systemd

setup_auto_login

#All commands ran successfully
echo "All necessary service installed successfully."
echo "You must reboot to complete a previous installation."
