# The tools make-retro.sh runs in a container (docs/M6.md §10): Debian 12's arj 3.10.22, its arc
# 5.21q built for i386 (on amd64 arc made only stored entries), zoo 2.10 from Debian 9 (the last
# Debian with it, from archive.debian.org), unar 1.10 and acefile (Python) as oracles, and
# libfaketime for the tools that stamp the time. make-retro.sh builds it as beezip-fixtures-retro.
FROM debian:9 AS zoo
RUN printf 'deb http://archive.debian.org/debian stretch main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update -qq \
    && cd / && apt-get download zoo

FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
COPY --from=zoo /zoo_*.deb /tmp/
RUN dpkg --add-architecture i386 \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        arj arc:i386 unar faketime python3 python3-pip gcc libc6-dev python3-dev /tmp/zoo_*.deb \
    && pip3 install -q --break-system-packages --no-cache-dir acefile==0.6.12 \
    && rm -rf /var/lib/apt/lists/* /tmp/zoo_*.deb
