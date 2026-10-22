# Every rule in one file: an unpinned base image, an index read in place and
# bytes fetched over a URL nobody controls.
FROM node:22.23.4
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl
ADD https://example.com/tool.tar.gz /usr/local/bin/tool
