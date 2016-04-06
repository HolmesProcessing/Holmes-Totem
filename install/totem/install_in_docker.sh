#!/bin/bash

DOCKERFILE=$(cat totem.dockerfile)
DOCKERFILE=$(echo "$DOCKERFILE" | sed -e 's~INSTALL_REPOSITORY~'$1'~')
echo "$DOCKERFILE" > "totem.dockerfile.modified"
docker build -t holmes_totem -f "totem.dockerfile.modified" .
rm "totem.dockerfile.modified"
