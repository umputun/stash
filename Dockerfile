FROM umputun/baseimage:buildgo-latest AS build

ARG GIT_BRANCH
ARG GITHUB_SHA
ARG CI

ADD . /build/stash
WORKDIR /build/stash

RUN \
    if [ -z "$CI" ] ; then \
    echo "runs outside of CI" && version=$(/script/git-rev.sh); \
    else version=${GIT_BRANCH}-${GITHUB_SHA:0:7}-$(date +%Y%m%dT%H:%M:%S); fi && \
    echo "version=$version" && \
    cd app && go build -o /build/stash/stash -ldflags "-X main.revision=${version} -s -w"


FROM umputun/baseimage:app-latest

LABEL org.opencontainers.image.source="https://github.com/umputun/stash"

COPY --from=build /build/stash/stash /srv/stash
RUN chmod +x /srv/stash

WORKDIR /srv

CMD ["/srv/stash", "server"]
ENTRYPOINT ["/init.sh"]
