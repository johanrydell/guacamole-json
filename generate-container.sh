#!/bin/bash
#
# Make sure your container is running with 
#

# Name of the running container passed as an argument
CONTAINER_NAME="$1"

# Check if the container name is provided
if [[ -z "$CONTAINER_NAME" ]]; then
  echo "Usage: $0 <container_name>"
  exit 1
fi

# Initialize variables
SYSTEMD="${HOME}/.config/systemd/user"
CONTAINERD="${HOME}/.config/containers/systemd"
CONTAINER_FILE="${CONTAINER_NAME}.container"


#
# Stop the service
#
stop() {
    local is_running=$(podman ps --format "{{.Names}}" | grep -c "^${CONTAINER_NAME}$")
    
    if [ -r "$SYSTEMD/${CONTAINER_NAME}.service" ] && [ "$is_running" -ne 0 ]; then
        systemctl --user stop "${CONTAINER_NAME}.service"
	is_running=$(podman ps --format "{{.Names}}" | grep -c "^${CONTAINER_NAME}$")
    fi

    if [ "$is_running" -ne 0 ]; then
        podman stop "${CONTAINER_NAME}"
    fi
    
    local is_present=$(podman ps -a --format "{{.Names}}" | grep -c "^${CONTAINER_NAME}$")
    if [ "$is_present" -ne 0 ]; then
        podman rm "${CONTAINER_NAME}"
    fi
}

#
# Volume
#
volume(){
    mounts=$(podman inspect --format '{{json .Mounts}}' "${CONTAINER_NAME}")

    # Use jq to parse and format the output as Volume=source:destination
    volumes=$(echo "$mounts" | jq -r '.[] | "Volume=" + .Source + ":" + .Destination')

    # Print the result
    echo  "$volumes" >> $1
}

#
# Create the .container file
#
create_file(){

    # Create a new file
    cat << EOF > "$CONTAINER_FILE"
[Install]
WantedBy=default.target

[Container]
EOF


    # Parse the command and extract commands
    podman inspect -f '{{json .Config.CreateCommand}}' ${CONTAINER_NAME} | sed 's%","%\n%g' | sed '1,2d' | sed 's%"\]%%' | while read line; do
	case $line in
	    --name=*)
		CONTAINER_NAME=`echo $line | cut -d '=' -f 2`
		echo "ContainerName=$CONTAINER_NAME" >> "$CONTAINER_FILE"
		;;
            --name)
		NEXT_IS="name"
		;;
            --hostname|-h)
		NEXT_IS="hostname"
		;;
            --publish|-p)
		NEXT_IS="port"
		;;
            --volume|-v)
		NEXT_IS="volume"
		;;
            --env|-e)
		NEXT_IS="env"
		;;
	    *)
		if [ -z "$NEXT_IS" ]; then
		    case $line in
			# We should not get this here, not supported
			/*|-*|run)
			;;
			*)
			    # This is the image followed by Exec
			    volume "$CONTAINER_FILE"
			    echo "Image=$line" >> "$CONTAINER_FILE"
			    NEXT_IS="first_cmd"
		    esac
		else
		    case $NEXT_IS in
			name)
			    echo "ContainerName=$line" >> "$CONTAINER_FILE"
			    NEXT_IS=""
			    ;;
			hostname)
			    echo "HostName=$line" >> "$CONTAINER_FILE"
			    NEXT_IS=""
			    ;;
			port)
			    echo "PublishPort=$line" >> "$CONTAINER_FILE"
			    NEXT_IS=""
			    ;;
			volume)
			    # this is managed just before iamge
			    #echo "Volume=$line" >> "$CONTAINER_FILE"
			    NEXT_IS=""
			    ;;
			env)
			    echo -n "Environment=">> "$CONTAINER_FILE"
			    # We need to add a quote if the line containes a space
			    echo "$line" | sed 's/=\(.* .*\)/="\1"/' >> "$CONTAINER_FILE"
			    NEXT_IS=""
			    ;;
			first_cmd)
			    echo -n "Exec=$line" >> "$CONTAINER_FILE"
			    NEXT_IS="next_cmd"
			    ;;
			next_cmd)
			    echo -n " $line" >> "$CONTAINER_FILE"
			    ;;
		    esac
		fi
		;;
	esac
    done


    # Create the .container file
    cat << EOF >> "$CONTAINER_FILE"


[Service]
Restart=always
#StandardOutput=null

EOF

    echo ".container file created: $CONTAINER_FILE"
}


#
# Check if the second argument is provided and equals "--activate"
#
activate() {
    if [[ "$2" == "--activate" ]]; then
	# Stop the service or podman container
	stop

	echo "Turning this into a systemd service: ${CONTAINER_NAME}.service"
	mkdir -p $CONTAINERD $SYSTEMD
	
	cp $CONTAINER_FILE $CONTAINERD/.
	
	# Creat the systemd files
	/usr/libexec/podman/quadlet -user -v  $SYSTEMD
	
	# reload the daemon
	systemctl --user daemon-reload
	systemctl --user enable ${CONTAINER_NAME}.service
	systemctl --user start ${CONTAINER_NAME}.service
	rm $CONTAINER_FILE
	echo "The new service is installed and running."
    else
	echo "You can create and enable ${CONTAINER_NAME} as a systemd service."
	echo "Use the argument --activate"
    fi
}

create_file
activate $@

#
# Use this to remove hardcoded user directories
#
#sed -i "s|$HOME|\${HOME}|g" "$CONTAINER_FILE"


