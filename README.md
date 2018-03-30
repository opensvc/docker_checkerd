# docker_checkerd
A poll-mode monitor daemon injecting alerts in the OpenSVC dashboard

# Deploy as a OpenSVC service

	echo '{
	    "DEFAULT": {
		"docker_daemon_private": "false",
		"nodes": "{clusternodes}",
		"orchestrate": "ha",
		"topology": "failover"
	    },
	    "container#1": {
		"run_args": "-it --rm -e COLLECTOR_PASSWORD={env.collector_password}",
		"run_command": "--user={env.collector_user} --api={env.collector_api} --insecure --name={env.checkerd_name} --workers={env.checkerd_workers} --janitor-interval={env.checkerd_janitor_interval} --update-unchanged-interval={env.checkerd_update_unchanged_interval} --foreground",
		"run_image": "opensvc/checkerd:latest",
		"type": "docker"
	    },
	    "env": {
		"collector_user": "me@acme.org",
		"collector_password": "{safe://55}",
		"collector_api": "https://10.0.3.3/init/rest/api",
		"checkerd_name": "{nodename}",
		"checkerd_workers": 5,
		"checkerd_janitor_interval": 35,
		"checkerd_update_unchanged_interval": 60
	    }
	}
	' | sudo svcmgr -s checkerd create
	sudo svcmgr -s checkerd edit config

