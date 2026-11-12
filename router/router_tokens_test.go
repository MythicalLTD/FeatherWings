package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/router/tokens"
)

// Invalid or expired tokens are answered with 401, not as a server error.
func TestInvalidTokensAreUnauthorized(t *testing.T) {
	h := newTransferHarness(t, &transferTestPanel{})

	expired, err := jwt.Sign(tokens.TransferPayload{
		Payload: jwt.Payload{
			Subject:        transferTestUUID,
			ExpirationTime: jwt.NumericDate(time.Now().Add(-time.Minute)),
		},
		Scoped: tokens.Scoped{Scope: string(tokens.ServerTransfer)},
	}, config.GetJwtAlgorithm())
	require.NoError(t, err)

	for name, token := range map[string]string{"expired": string(expired), "malformed": "not-a-jwt"} {
		t.Run(name, func(t *testing.T) {
			archive := buildTransferTestArchive(t, map[string]string{"received.txt": "data"})
			body, contentType := transferTestMultipart(t, archive, strings.Repeat("0", 64))
			w := h.postTransfer(body, contentType, token)
			assert.Equal(t, http.StatusUnauthorized, w.Code, "/api/transfers")

			for _, path := range []string{"/download/file", "/download/backup"} {
				req := httptest.NewRequest(http.MethodGet, path+"?token="+token, nil)
				w := httptest.NewRecorder()
				h.router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusUnauthorized, w.Code, path)
			}
		})
	}
}
