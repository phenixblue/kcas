FROM alpine:latest

LABEL org.opencontainers.image.authors="Joe Searcy <joe@twr.io"
LABEL org.opencontainers.image.source="https://github.com/phenixblue/kcas"

RUN addgroup -g 1900 kcas
RUN adduser -u 1900 -G kcas --disabled-password kcas

ENV PORT 5555
EXPOSE $PORT

COPY bin/kcas /
RUN chown kcas:kcas /kcas
USER kcas

CMD ["/kcas"]