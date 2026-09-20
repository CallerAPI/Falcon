# Falcon Zoom demo

Two 30-day stores. Same INVITEs. Free names cloud and abuse lists. Paid names the voice operator and drops listed spam DIDs.

```
cd falcon
go run ./cmd/falcon demo seed
FALCON_DEMO=true FALCON_DEMO_PROFILE=free FALCON_ALLOW_OPEN=true \
  FALCON_DB_PATH=./examples/demo/live.db FALCON_LISTEN=127.0.0.1:8090 \
  go run ./cmd/falcon
```

Dashboard: http://127.0.0.1:8090/

On the call, flip the profile:

```
FALCON_TOKEN= FALCON_DEMO_URL=http://127.0.0.1:8090 go run ./cmd/falcon demo swap paid
```

Refresh the 30 day range. Providers become 8x8, Zoom, Piratel. Rejects rise. Spam DIDs from the 15-day feed drop.

`falcon demo swap free` puts the OSS view back.

Rebuild the CIDR files from the lookup store:

```
python3 /Users/dimon/Downloads/ip_to_org/export_falcon.py --demo-out examples/demo
```
