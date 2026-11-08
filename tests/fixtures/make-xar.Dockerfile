# The tools make-xar.sh runs in a container (docs/M6.md §10): xar 1.6.1 (mackyle's, the last
# open-source xar outside Apple, built from its repository at a fixed commit), Ubuntu 24.04's
# bsdtar 3.7.2 (libarchive-tools), bomutils' mkbom and lsbom (built at a fixed commit), GNU cpio,
# gzip, xz and Python for the pbzx writer, with libfaketime for the tools that stamp the time.
# make-xar.sh builds it as beezip-fixtures-xar.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        libarchive-tools cpio gzip bzip2 xz-utils faketime python3 ca-certificates git \
        build-essential autoconf automake libtool libxml2-dev libssl-dev zlib1g-dev libbz2-dev liblzma-dev \
    && rm -rf /var/lib/apt/lists/*
# xar 1.6.1 at mackyle/xar 66d451d (2014); OpenSSL 3 has no OpenSSL_add_all_ciphers.
RUN git clone -q https://github.com/mackyle/xar.git /build/xar \
    && cd /build/xar && git checkout -q 66d451dab1ef859dd0c83995f2379335d35e53c9 \
    && cd xar && sed -i 's/OpenSSL_add_all_ciphers/OPENSSL_init_crypto/' configure.ac \
    && ./autogen.sh --noconfigure >/dev/null && ./configure -q --prefix=/usr/local >/dev/null \
    && make -s -j4 >/dev/null 2>&1 && make -s install >/dev/null && ldconfig
# bomutils at hogliux/bomutils c247002 (2024-10-28).
RUN git clone -q https://github.com/hogliux/bomutils.git /build/bomutils \
    && cd /build/bomutils && git checkout -q c247002e2f49878bab32dd0fcf805810ae0992cb \
    && make -s >/dev/null 2>&1 && cp build/bin/mkbom build/bin/lsbom /usr/local/bin/
