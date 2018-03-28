# docker_checkerd
A poll-mode monitor daemon injecting alerts in the OpenSVC dashboard

# deploy as a OpenSVC service

::

	echo '{
	    "DEFAULT": {
		"docker_daemon_private": "false",
		"nodes": "{clusternodes}",
		"orchestrate": "ha",
		"topology": "failover"
	    },
	    "container#1": {
		"run_args": "-it --rm -e COLLECTOR_PASSWORD={env.password}",
		"run_command": "--user={env.user} --api={env.api} --insecure --name={env.name} --workers={env.workers} --janitor-interval={env.janitor_interval} --update-unchanged-interval={env.update_unchanged_interval} --foreground",
		"run_image": "opensvc/checkerd:latest",
		"type": "docker"
	    },
	    "env": {
		"user": "me@acme.org",
		"password": "{safe://55}",
		"api": "https://10.0.3.3/init/rest/api",
		"name": "{nodename}",
		"workers": 5,
		"janitor_interval": 35,
		"update_unchanged_interval": 60
	    }
	}
	' | sudo svcmgr -s checkerd create --interactive

