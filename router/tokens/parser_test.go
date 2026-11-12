package tokens

import (
	"errors"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"

	"github.com/mythicalltd/featherwings/config"
)

func signTestToken(t *testing.T, exp time.Time) string {
	t.Helper()
	token, err := jwt.Sign(BackupPayload{
		Payload: jwt.Payload{ExpirationTime: jwt.NumericDate(exp)},
	}, config.GetJwtAlgorithm())
	if err != nil {
		t.Fatal(err)
	}
	return string(token)
}

// ParseToken reports malformed, badly signed and expired tokens as
// ErrInvalidToken while still matching the underlying jwt error and keeping its
// message, which websocket clients receive.
func TestParseTokenWrapsJwtErrors(t *testing.T) {
	config.Set(&config.Configuration{AuthenticationToken: "test-token"})

	var payload BackupPayload
	err := ParseToken([]byte(signTestToken(t, time.Now().Add(-time.Minute))), &payload)
	if !errors.Is(err, ErrInvalidToken) || !errors.Is(err, jwt.ErrExpValidation) {
		t.Fatalf("expected the error to match both ErrInvalidToken and jwt.ErrExpValidation, got %v", err)
	}
	if err.Error() != jwt.ErrExpValidation.Error() {
		t.Errorf("expected the jwt error message %q, got %q", jwt.ErrExpValidation.Error(), err.Error())
	}

	valid := signTestToken(t, time.Now().Add(15*time.Minute))
	for name, bad := range map[string]string{
		"bad signature": valid[:len(valid)-4] + "AAAA",
		"malformed":     "not-a-jwt",
		"empty":         "",
	} {
		if err := ParseToken([]byte(bad), &payload); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: expected ErrInvalidToken, got %v", name, err)
		}
	}

	if err := ParseToken([]byte(valid), &payload); err != nil {
		t.Fatalf("expected a valid token to parse, got %v", err)
	}
}
