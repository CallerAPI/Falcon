# Real Asterisk for the adapter test. Alpine's package, the AGI's Python.
FROM alpine:3.20
RUN apk add --no-cache asterisk python3 \
  && rm -f /etc/asterisk/*.conf \
  && mkdir -p /var/lib/asterisk/agi-bin /var/spool/asterisk /var/log/asterisk /var/run/asterisk
COPY asterisk.conf modules.conf logger.conf pjsip.conf rtp.conf extensions.conf /etc/asterisk/
CMD ["asterisk", "-f", "-vvv"]
