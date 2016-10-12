#Shodan service for Holmes-Totem

###Description
A simple service for gathering Shodan information about an ip address.

###Usage
Build and start the docker container using the included Dockerfile.
If the service has frequent timeouts you have to adjust totem.conf:
- totem.download_settings.connection_timeout
- totem.download_settings.request_timeout
- totem.tasking_settings.default_service_timeout
