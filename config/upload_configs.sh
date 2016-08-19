#!/bin/sh
if [[ $# -eq 0 ]] ; then
	echo "Please specify the IP Address and the Port of Holmes-Storage, e.g.:"
	echo "./upload_configs.sh 127.0.0.1:8017"
	exit 0
fi

export CONFSTORAGE=http://${1}/config/services/
for i in ../src/main/scala/org/holmesprocessing/totem/services/*
do
	service=$(basename $i)
	echo $service
	if [ -e $i/service.conf ]
	then
		echo "using service.conf"
		read -p "continue uploading? [yN] "
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			curl -F config=@$i/service.conf ${CONFSTORAGE}${service}/service.conf
		fi
		echo ""
	elif [ -e $i/service.conf.example ]
	then
		echo "using service.conf.example"
		read -p "continue uploading? [yN]"
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			curl -F config=@$i/service.conf.example ${CONFSTORAGE}${service}/service.conf
		fi
		echo ""
	else
		echo "NO CONFIGURATION!"
	fi
done
