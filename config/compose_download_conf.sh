#!/bin/sh
if [[ $# -eq 0 ]] ; then
	echo "Please specify the IP Address and the Port of Holmes-Storage, e.g.:"
	echo "./compose_download_conf.sh 127.0.0.1:8017"
	exit 0
fi

export CONFSTORAGE=http://${1}/config/services/

export CONFSTORAGE_ASNMETA=${CONFSTORAGE}asnmeta/
export CONFSTORAGE_DNSMETA=${CONFSTORAGE}dnsmeta/
export CONFSTORAGE_PASSIVETOTAL=${CONFSTORAGE}passivetotal/
export CONFSTORAGE_GOGADGET=${CONFSTORAGE}gogadget/
export CONFSTORAGE_OBJDUMP=${CONFSTORAGE}objdump/
export CONFSTORAGE_PEID=${CONFSTORAGE}peid/
export CONFSTORAGE_PEINFO=${CONFSTORAGE}peinfo/
export CONFSTORAGE_VIRUSTOTAL=${CONFSTORAGE}virustotal/
export CONFSTORAGE_YARA=${CONFSTORAGE}yara/
export CONFSTORAGE_ZIPMETA=${CONFSTORAGE}zipmeta/
docker-compose -f ./docker-compose.yml.example up -d --build
