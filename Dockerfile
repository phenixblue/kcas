FROM scratch

ENV PORT 5555
EXPOSE $PORT

COPY kcas /
CMD ["/kcas"]