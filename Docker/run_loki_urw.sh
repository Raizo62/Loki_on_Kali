docker run \
	--privileged --network=host					\
	--rm										\
	--volume /tmp/:/tmp/						\
	--env DISPLAY --env XAUTHORITY='/xauthority' --volume /tmp/.X11-unix/:/tmp/.X11-unix/ --volume ${XAUTHORITY}:/xauthority:ro \
	--interactive --tty --entrypoint /usr/bin/loki_urw.py \
	loki_on_kali:latest
