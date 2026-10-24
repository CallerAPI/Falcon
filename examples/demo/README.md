# Falcon Zoom demo

Two 30-day stores. Same INVITEs. Free names cloud and abuse lists. Paid names the voice operator and drops listed spam numbers.

Every carrier, address, and phone number in the demo is fictional. The addresses are in the RFC 5737 documentation ranges.

```
cd falcon
make build
./bin/falcon demo seed
FALCON_DEMO=true FALCON_DEMO_PROFILE=free FALCON_ALLOW_OPEN=true \
  FALCON_DB_PATH=./examples/demo/live.db FALCON_LISTEN=127.0.0.1:8090 \
  ./bin/falcon
```

Dashboard: http://127.0.0.1:8090/

On the call, flip the profile:

```
FALCON_TOKEN= FALCON_DEMO_URL=http://127.0.0.1:8090 ./bin/falcon demo swap paid
```

Refresh the 30 day range. Providers become Northwind Voice, Bluepeak Communications, and Graystone Gateway. Rejects rise. Numbers on the demo spam list drop.

`./bin/falcon demo swap free` puts the OSS view back.

The fixtures are `ipintel-free.csv`, `ipintel-paid.csv`, and `spam_dids.txt`. Edit them by hand. Keep the addresses in 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24, and the spam numbers in 555-0100 to 555-0199.
