FROM bitnami/minideb:stretch

LABEL version="2.0" maintainer="Raizo62 <https://github.com/Raizo62>"

COPY run_by_dockerfile.sh .
RUN bash ./run_by_dockerfile.sh

ENTRYPOINT /usr/bin/loki_gtk.py
