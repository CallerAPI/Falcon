package sdk

import "testing"

func voiceBridge() Bridge {
	return Bridge{
		Transport: "websocket",
		URL:       "wss://app.connexcs.com/api/cp/scriptforge/{script_id}",
		Headers:   map[string]string{"Authorization": "Bearer {token}"},
		Sink:      SinkVoiceTranscript,
		Settings: []BridgeSetting{
			{Key: "script_id", Label: "Script id", Pattern: "^[0-9]{1,12}$"},
			{Key: "token", Label: "Access token", Secret: true},
		},
	}
}

func TestBridgeAllowsCatalogWebsocket(t *testing.T) {
	b := voiceBridge()
	if err := ValidateBridge(b); err != nil {
		t.Fatal(err)
	}
	raw, headers, err := b.Materialize(map[string]string{"script_id": "10141", "token": "opaque"})
	if err != nil {
		t.Fatal(err)
	}
	if raw != "wss://app.connexcs.com/api/cp/scriptforge/10141" || headers["Authorization"] != "Bearer opaque" {
		t.Fatalf("%s %v", raw, headers)
	}
}

func TestBridgeRejectsUnsafeCatalog(t *testing.T) {
	cases := []Bridge{
		{Transport: "http", URL: "wss://app.connexcs.com/x", Sink: SinkVoiceTranscript, Settings: []BridgeSetting{{Key: "a", Label: "A"}}},
		{Transport: "websocket", URL: "ws://app.connexcs.com/x", Sink: SinkVoiceTranscript, Settings: []BridgeSetting{{Key: "a", Label: "A"}}},
		{Transport: "websocket", URL: "wss://127.0.0.1/x", Sink: SinkVoiceTranscript, Settings: []BridgeSetting{{Key: "a", Label: "A"}}},
		{Transport: "websocket", URL: "wss://user:pass@app.connexcs.com/x", Sink: SinkVoiceTranscript, Settings: []BridgeSetting{{Key: "a", Label: "A"}}},
		{Transport: "websocket", URL: "wss://app.connexcs.com/x", Sink: "shell", Settings: []BridgeSetting{{Key: "a", Label: "A"}}},
		{Transport: "websocket", URL: "wss://{host}/x", Sink: SinkVoiceTranscript, Settings: []BridgeSetting{{Key: "host", Label: "Host"}}},
		{Transport: "websocket", URL: "wss://app.connexcs.com/x", Sink: SinkVoiceTranscript, Headers: map[string]string{"Cookie": "a"}, Settings: []BridgeSetting{{Key: "a", Label: "A"}}},
	}
	for i, b := range cases {
		if err := ValidateBridge(b); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	b := voiceBridge()
	if _, _, err := b.Materialize(map[string]string{"script_id": "nope", "token": "x"}); err == nil {
		t.Fatal("bad script id")
	}
}
