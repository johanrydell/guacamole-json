#!/bin/bash

if [ -z "$1" ]; then
    podman save -o guacamole-json_latest.tar localhost/guacamole-json:latest
else
    podman save -o guacamole-json_${1}.tar localhost/guacamole-json:${1}
fi

