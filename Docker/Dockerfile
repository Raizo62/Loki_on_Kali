FROM bitnami/minideb:buster

LABEL version="1.0" maintainer="Raizo62 <https://github.com/Raizo62>"

COPY install-loki.sh .
RUN bash ./install-loki.sh

ENTRYPOINT /usr/bin/loki_gtk.py
