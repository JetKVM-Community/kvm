package kvm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// One password for the web UI, Redfish and IPMI.
//
// Those three cannot all verify it the same way. Web and Redfish receive the
// password and check it, so a one-way bcrypt hash is the right store and stays
// the authority. IPMI cannot: RMCP+ RAKP has the BMC compute an HMAC *keyed
// with the password* before the console has proven anything, and derives the
// session's integrity and confidentiality keys from it. A verifier that is
// useless to an attacker is equally useless to the BMC, so IPMI needs the
// bytes back.
//
// So the password is stored twice: bcrypt for web/Redfish, and separately
// encrypted for IPMI. This is what OpenBMC does (phosphor-ipmi-host keeps
// /etc/ipmi_pass AES-encrypted under /etc/key_file) for the same unavoidable
// reason.
//
// Two things bound the cost, because reversible storage of the *web* password
// is a genuine reduction in what a filesystem-read attacker gets:
//
//   - The encrypted copy exists only while BMC mode is on. Turn it off and it
//     is erased, and the device is back to bcrypt-only.
//   - bcrypt remains the authority for web and Redfish. The encrypted copy is
//     never consulted to authenticate a human; it exists solely as RAKP key
//     material.
//
// The honest limit: the key lives on the same device as the ciphertext, so this
// stops a leaked config file, a backup, or a support bundle from disclosing the
// password. It does not stop someone who already has root on the device. No
// implementation of IPMI can do better than that -- the protocol requires the
// secret to be recoverable at runtime.

const credKeyPath = "/userdata/jetkvm/.credkey"

var (
	credKeyOnce sync.Once
	credKey     []byte
	credKeyErr  error
)

// credentialKey returns the device-local key, creating it on first use.
func credentialKey() ([]byte, error) {
	credKeyOnce.Do(func() {
		if data, err := os.ReadFile(credKeyPath); err == nil && len(data) == 32 {
			credKey = data
			return
		}

		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			credKeyErr = fmt.Errorf("generate credential key: %w", err)
			return
		}
		// 0600: the whole point is that reading the config is not enough.
		if err := os.WriteFile(credKeyPath, key, 0o600); err != nil {
			credKeyErr = fmt.Errorf("write credential key: %w", err)
			return
		}
		credKey = key
	})
	return credKey, credKeyErr
}

// encryptCredential seals a password with AES-256-GCM. GCM rather than CBC so
// the ciphertext is authenticated: a tampered blob fails to open instead of
// decrypting to rubbish that then gets used as an HMAC key.
func encryptCredential(plain string) (string, error) {
	key, err := credentialKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptCredential opens what encryptCredential sealed.
func decryptCredential(encoded string) (string, error) {
	if encoded == "" {
		return "", fmt.Errorf("no stored credential")
	}

	key, err := credentialKey()
	if err != nil {
		return "", err
	}

	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode credential: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize() {
		return "", fmt.Errorf("stored credential is truncated")
	}

	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("open credential: %w", err)
	}
	return string(plain), nil
}

// setSharedPassword records a new password in both forms.
//
// The encrypted copy is written only when BMC mode is on, so a device that is
// not acting as a BMC never carries a reversible copy of its own password.
func setSharedPassword(plain string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	config.HashedPassword = string(hashed)

	if !bmcModeEnabled() {
		config.EncryptedPassword = ""
	} else if sealed, err := encryptCredential(plain); err != nil {
		// Not fatal: the password is set and web/Redfish work. IPMI will refuse
		// to start rather than run with a stale credential.
		config.EncryptedPassword = ""
		logger.Error().Err(err).Msg("failed to store the IPMI credential; IPMI will not start")
	} else {
		config.EncryptedPassword = sealed
	}

	// A new password invalidates every cached verification.
	bcryptCacheReset()

	// IPMI reads the credential once, when it starts. Without this, setting the
	// device password on a BMC whose IPMI had no credential yet leaves the
	// listener down until the next reboot -- and enabling IPMI, then setting a
	// password, is the obvious order to do it in.
	if bmcModeEnabled() {
		if err := ipmiRestart(); err != nil {
			ipmiLogger.Error().Err(err).Msg("failed to restart IPMI after a password change")
		}
	}

	return nil
}

// clearSharedPassword removes the password in both forms.
//
// Both, not just the bcrypt hash: leaving the sealed copy behind would let IPMI
// keep authenticating a password the operator has just deleted, which is the
// opposite of what "remove the password" means.
func clearSharedPassword() {
	config.HashedPassword = ""
	config.EncryptedPassword = ""
	bcryptCacheReset()
}

// sharedPasswordForIPMI returns the plaintext RAKP needs.
func sharedPasswordForIPMI() (string, error) {
	if config.EncryptedPassword == "" {
		return "", fmt.Errorf("no shared credential is stored; set the device password with BMC mode enabled")
	}
	return decryptCredential(config.EncryptedPassword)
}

// --- bcrypt verification cache ---------------------------------------------
//
// bcrypt is deliberately slow -- ~50-100ms at the default cost. That is correct
// for a login form and wrong for Redfish, where the host's firmware makes dozens
// of authenticated requests during a single boot and pays the cost on every one.
//
// Only *successful* verifications are cached. Caching failures would remove the
// rate limiting that bcrypt's slowness provides against guessing, which is the
// property being relied on here.
//
// The cache key is HMAC(per-boot random key, password) rather than the password
// or a bare digest of it: the key is regenerated each boot, so the stored value
// is not precomputable and does not survive a restart.

const (
	bcryptCacheTTL     = 10 * time.Minute
	bcryptCacheMaxSize = 8
)

type bcryptCacheEntry struct {
	digest  []byte // HMAC of the password
	hash    string // the bcrypt hash it was verified against
	expires time.Time
}

var (
	bcryptCacheMu  sync.Mutex
	bcryptCache    []bcryptCacheEntry
	bcryptCacheKey []byte
	bcryptKeyOnce  sync.Once
)

func bcryptCacheDigest(password string) []byte {
	bcryptKeyOnce.Do(func() {
		bcryptCacheKey = make([]byte, 32)
		if _, err := rand.Read(bcryptCacheKey); err != nil {
			// Without a key the cache cannot be keyed safely, so disable it by
			// leaving the key nil and always falling through to bcrypt.
			bcryptCacheKey = nil
		}
	})
	if bcryptCacheKey == nil {
		return nil
	}

	mac := hmac.New(sha256.New, bcryptCacheKey)
	mac.Write([]byte(password))
	return mac.Sum(nil)
}

func bcryptCacheReset() {
	bcryptCacheMu.Lock()
	bcryptCache = nil
	bcryptCacheMu.Unlock()
}

// verifyPassword checks a password against the configured hash, memoising
// successes. Semantics are identical to calling bcrypt directly.
func verifyPassword(password string) bool {
	hash := config.HashedPassword
	if hash == "" {
		return false
	}

	digest := bcryptCacheDigest(password)
	now := time.Now()

	if digest != nil {
		bcryptCacheMu.Lock()
		for _, e := range bcryptCache {
			// Constant-time on the digest: a timing signal here would leak
			// which passwords are in the cache.
			if e.hash == hash && now.Before(e.expires) &&
				subtle.ConstantTimeCompare(e.digest, digest) == 1 {
				bcryptCacheMu.Unlock()
				return true
			}
		}
		bcryptCacheMu.Unlock()
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false
	}

	if digest != nil {
		bcryptCacheMu.Lock()
		// Drop anything expired or verified against a superseded hash before
		// bounding, so a password change cannot be masked by a stale entry.
		kept := bcryptCache[:0]
		for _, e := range bcryptCache {
			if e.hash == hash && now.Before(e.expires) {
				kept = append(kept, e)
			}
		}
		bcryptCache = kept
		if len(bcryptCache) >= bcryptCacheMaxSize {
			bcryptCache = bcryptCache[1:]
		}
		bcryptCache = append(bcryptCache, bcryptCacheEntry{
			digest:  digest,
			hash:    hash,
			expires: now.Add(bcryptCacheTTL),
		})
		bcryptCacheMu.Unlock()
	}

	return true
}
