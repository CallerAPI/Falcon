// Package identity gives an install a stable Ed25519 key pair. Telemetry and
// feed requests are signed with it, so CallerAPI can tell one install from
// another without an account and can refuse a post that claims an install id
// it does not hold the key for. The private key never leaves the host.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

const kvSeed = "install_key_seed"

// Header names on signed requests.
const (
	HeaderInstall   = "X-Falcon-Install"
	HeaderKey       = "X-Falcon-Key"
	HeaderTimestamp = "X-Falcon-Timestamp"
	HeaderSignature = "X-Falcon-Signature"
	// Prefix pins the signed string format. Bump with any change.
	Prefix = "falcon-v1"
)

// Key is an install's signing identity.
type Key struct {
	InstallID string
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
}

// Load returns the stored key, creating one on first use.
func Load(ctx context.Context, db store.Store, installID string) (*Key, error) {
	if installID == "" {
		return nil, errors.New("identity: empty install id")
	}
	seedHex, err := db.KVGet(ctx, kvSeed)
	if err != nil {
		return nil, err
	}
	var seed []byte
	if seedHex != "" {
		seed, err = hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("identity: stored key seed is corrupt")
		}
	} else {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := db.KVSet(ctx, kvSeed, hex.EncodeToString(seed)); err != nil {
			return nil, err
		}
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Key{InstallID: installID, priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// Public is the base64 public key sent on every request.
func (k *Key) Public() string {
	return base64.RawURLEncoding.EncodeToString(k.pub)
}

// Message is the exact string signed. Both sides build it the same way:
// prefix, install id, unix time, method, path, and the body digest.
func Message(installID string, ts int64, method, path string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(Prefix + "\n" + installID + "\n" + strconv.FormatInt(ts, 10) + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(sum[:]))
}

// Sign adds the identity headers to a request.
func (k *Key) Sign(req *http.Request, body []byte) {
	ts := time.Now().Unix()
	sig := ed25519.Sign(k.priv, Message(k.InstallID, ts, req.Method, req.URL.Path, body))
	req.Header.Set(HeaderInstall, k.InstallID)
	req.Header.Set(HeaderKey, k.Public())
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(sig))
}

// Verify checks a signed request the way the server does. Skew bounds the
// timestamp. Returns the install id and public key on success.
func Verify(r *http.Request, body []byte, skew time.Duration) (installID string, pubKey []byte, err error) {
	installID = r.Header.Get(HeaderInstall)
	keyB64 := r.Header.Get(HeaderKey)
	tsStr := r.Header.Get(HeaderTimestamp)
	sigB64 := r.Header.Get(HeaderSignature)
	if installID == "" || keyB64 == "" || tsStr == "" || sigB64 == "" {
		return "", nil, errors.New("identity headers missing")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", nil, errors.New("bad timestamp")
	}
	if d := time.Since(time.Unix(ts, 0)); d > skew || d < -skew {
		return "", nil, errors.New("timestamp outside allowed skew")
	}
	pubKey, err = base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return "", nil, errors.New("bad public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", nil, errors.New("bad signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), Message(installID, ts, r.Method, r.URL.Path, body), sig) {
		return "", nil, errors.New("signature does not verify")
	}
	return installID, pubKey, nil
}
