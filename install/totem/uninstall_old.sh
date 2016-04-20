#!/bin/bash

if [[ -f "${OPT[path]}/uninstall.sh" ]]; then
    cd "${OPT[path]}"
    (uninstall.sh --keep-docker --remove-data --keep-sbt --keep-java8)
    cd "$WORKING_DIRECTORY"
fi
sudo rm -rf "${OPT[path]}" &>/dev/null
