package router

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/remote"
	"github.com/mythicalltd/featherwings/router/tokens"
	wserver "github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/transfer"
)

// transferTestUUID is a lowercase version 4 UUID, as the installer requires.
const transferTestUUID = "3f0c9a52-7d1e-4b8a-9c2f-5e6d7a8b9c01"

// transferTestPanel answers the Panel calls made by the transfer handlers. Only
// the calls these tests reach are implemented; any other call panics on the nil
// embedded interface.
type transferTestPanel struct {
	remote.Client

	mu        sync.Mutex
	config    remote.ServerConfigurationResponse
	statusErr error
	statuses  []bool
}

func (p *transferTestPanel) GetServerConfiguration(context.Context, string) (remote.ServerConfigurationResponse, error) {
	return p.config, nil
}

func (p *transferTestPanel) SetTransferStatus(_ context.Context, _ string, successful bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statuses = append(p.statuses, successful)
	return p.statusErr
}

// transferTestEnvironment stands in for the Docker environment so that no
// container is needed.
type transferTestEnvironment struct {
	environment.ProcessEnvironment
}

func (transferTestEnvironment) Create() error { return nil }

func (transferTestEnvironment) State() string { return environment.ProcessOfflineState }

func (transferTestEnvironment) Destroy() error { return nil }

type transferHarness struct {
	t      *testing.T
	router http.Handler
	mgr    *wserver.Manager
	panel  *transferTestPanel
}

// newTransferHarness builds the full router with a temporary data directory and
// a node token of "test-token".
func newTransferHarness(t *testing.T, panel *transferTestPanel) *transferHarness {
	t.Helper()

	root := t.TempDir()
	cfg, err := config.NewAtPath(filepath.Join(root, "config.yml"))
	require.NoError(t, err)
	cfg.AuthenticationToken = "test-token"
	cfg.System.Data = filepath.Join(root, "volumes")
	cfg.System.MachineID.Enable = false
	cfg.System.BackupDirectory = filepath.Join(root, "backups")
	config.Set(cfg)

	settings, err := json.Marshal(map[string]string{"uuid": transferTestUUID})
	require.NoError(t, err)
	panel.config = remote.ServerConfigurationResponse{
		Settings:             settings,
		ProcessConfiguration: &remote.ProcessConfiguration{},
	}

	// A failed transfer whose container could not be removed (there is no Docker
	// in tests) keeps its claim on purpose; start every test without one.
	incomingClaims.release(transferTestUUID)
	t.Cleanup(func() { incomingClaims.release(transferTestUUID) })

	mgr := wserver.NewEmptyManager(panel)
	return &transferHarness{t: t, router: Configure(mgr, panel), mgr: mgr, panel: panel}
}

// seedServer registers the test server on the manager, as an earlier receive
// would have, and replaces its Docker environment.
func (h *transferHarness) seedServer() *wserver.Server {
	h.t.Helper()

	s, err := h.mgr.InitServer(transferTestUUID, h.panel.config)
	require.NoError(h.t, err)
	s.Environment = transferTestEnvironment{}
	require.True(h.t, h.mgr.AddIfMissing(s))
	return s
}

// startInFlightReceive marks the server as receiving a transfer, the way the
// first POST /api/transfers request does.
func (h *transferHarness) startInFlightReceive(s *wserver.Server) *transfer.Transfer {
	h.t.Helper()

	s.SetTransferring(true)
	tr := transfer.New(context.Background(), s)
	require.True(h.t, transfer.Incoming().Add(tr))
	h.t.Cleanup(func() { transfer.Incoming().Remove(tr) })
	return tr
}

func (h *transferHarness) postTransfer(body *bytes.Buffer, contentType, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/transfers", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

func buildTransferTestArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func transferTestMultipart(t *testing.T, archive []byte, checksum string) (*bytes.Buffer, string) {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("archive", "archive.tar.gz")
	require.NoError(t, err)
	_, err = part.Write(archive)
	require.NoError(t, err)
	require.NoError(t, mw.WriteField("checksum", checksum))
	require.NoError(t, mw.Close())
	return &buf, mw.FormDataContentType()
}

// signTransferTestToken issues a transfer JWT with the same claims the Panel
// sets: subject is the server UUID, scope is "transfer", and it expires after
// 15 minutes.
func signTransferTestToken(t *testing.T, subject string) string {
	t.Helper()

	token, err := jwt.Sign(tokens.TransferPayload{
		Payload: jwt.Payload{
			Subject:        subject,
			ExpirationTime: jwt.NumericDate(time.Now().Add(15 * time.Minute)),
		},
		Scoped: tokens.Scoped{Scope: string(tokens.ServerTransfer)},
	}, config.GetJwtAlgorithm())
	require.NoError(t, err)
	return string(token)
}

// A receive whose checksum does not match does not leave the extracted files on
// disk.
func TestTransferChecksumMismatchRemovesExtractedFiles(t *testing.T) {
	h := newTransferHarness(t, &transferTestPanel{})

	archive := buildTransferTestArchive(t, map[string]string{"received.txt": "data"})
	body, contentType := transferTestMultipart(t, archive, strings.Repeat("0", 64))

	w := h.postTransfer(body, contentType, signTransferTestToken(t, transferTestUUID))
	require.NotEqual(t, http.StatusOK, w.Code)

	_, err := os.Stat(filepath.Join(config.Get().System.Data, transferTestUUID, "received.txt"))
	assert.True(t, os.IsNotExist(err), "a file from a failed receive is still on disk")
	_, registered := h.mgr.Get(transferTestUUID)
	assert.False(t, registered)
}

// A second request to send a server that is already being received is refused,
// and does not affect the transfer in progress.
func TestTransferThatIsAlreadyInProgressIsRefused(t *testing.T) {
	panel := &transferTestPanel{}
	h := newTransferHarness(t, panel)
	s := h.seedServer()
	h.startInFlightReceive(s)

	archive := buildTransferTestArchive(t, map[string]string{"second.dat": "data"})
	body, contentType := transferTestMultipart(t, archive, strings.Repeat("0", 64))

	w := h.postTransfer(body, contentType, signTransferTestToken(t, transferTestUUID))
	require.Equal(t, http.StatusConflict, w.Code)

	_, registered := h.mgr.Get(transferTestUUID)
	assert.True(t, registered)
	assert.True(t, s.IsTransferring())
	assert.Empty(t, panel.statuses)
}

// A successful transfer is finished even if the Panel cannot be told about it,
// so that the server is not left unable to start.
func TestCompletedTransferIsFinishedWhenPanelFails(t *testing.T) {
	panel := &transferTestPanel{statusErr: errors.New("panel unavailable")}
	h := newTransferHarness(t, panel)
	s := h.seedServer()
	tr := h.startInFlightReceive(s)

	completeIncomingTransfer(h.mgr, tr, true, incomingTransferFiles{})

	assert.False(t, s.IsTransferring())
	assert.Nil(t, transfer.Incoming().Get(transferTestUUID))
	assert.Equal(t, []bool{true}, panel.statuses)
}

// A failed transfer removes the server and the files that were received.
func TestFailedTransferRemovesReceivedServer(t *testing.T) {
	panel := &transferTestPanel{}
	h := newTransferHarness(t, panel)
	s := h.seedServer()
	tr := h.startInFlightReceive(s)
	require.NoError(t, s.EnsureDataDirectoryExists())
	require.NoError(t, os.WriteFile(filepath.Join(s.Filesystem().Path(), "received.txt"), []byte("data"), 0o644))

	completeIncomingTransfer(h.mgr, tr, false, incomingTransferFiles{})

	_, registered := h.mgr.Get(transferTestUUID)
	assert.False(t, registered)
	_, err := os.Stat(s.Filesystem().Path())
	assert.True(t, os.IsNotExist(err))
	assert.Equal(t, []bool{false}, panel.statuses)
}

// An outbound transfer does not start while the server is being restored.
func TestPostServerTransferRejectsRestoringServer(t *testing.T) {
	h := newTransferHarness(t, &transferTestPanel{})
	s := h.seedServer()
	s.SetRestoring(true)

	payload := []byte(`{"url":"http://127.0.0.1:1/api/transfers","token":"Bearer test","server":{"uuid":"` +
		transferTestUUID + `","start_on_completion":false}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/servers/"+transferTestUUID+"/transfer", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.False(t, s.IsTransferring())
}

// Cancelling an incoming transfer that does not exist is refused, rather than
// failing with a server error.
func TestDeleteTransferForUnknownServer(t *testing.T) {
	h := newTransferHarness(t, &transferTestPanel{})

	req := httptest.NewRequest(http.MethodDelete, "/api/transfers/"+transferTestUUID, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// A failed transfer on a shared storage pool never deletes the server's data
// directory: it is the source node's live data.
func TestFailedPooledTransferKeepsSourceData(t *testing.T) {
	panel := &transferTestPanel{}
	h := newTransferHarness(t, panel)
	s := h.seedServer()
	tr := h.startInFlightReceive(s)
	require.NoError(t, s.EnsureDataDirectoryExists())
	live := filepath.Join(s.Filesystem().Path(), "world.dat")
	require.NoError(t, os.WriteFile(live, []byte("live data"), 0o644))

	ok := completeIncomingTransfer(h.mgr, tr, false, incomingTransferFiles{pooled: true})

	assert.True(t, ok)
	b, err := os.ReadFile(live)
	require.NoError(t, err, "the source's data was deleted by a failed pooled transfer")
	assert.Equal(t, "live data", string(b))
	_, registered := h.mgr.Get(transferTestUUID)
	assert.False(t, registered)
	assert.Equal(t, []bool{false}, panel.statuses)
}

// A pooled request whose environment cannot be created leaves the shared data
// directory alone.
func TestPooledTransferFailureOverHTTPKeepsSourceData(t *testing.T) {
	h := newTransferHarness(t, &transferTestPanel{})
	cfg := config.Get()
	cfg.System.Transfers.StoragePool.Enabled = true
	cfg.System.Transfers.StoragePool.PoolName = "shared"
	config.Set(cfg)

	dataDir := filepath.Join(cfg.System.Data, transferTestUUID)
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	live := filepath.Join(dataDir, "world.dat")
	require.NoError(t, os.WriteFile(live, []byte("live data"), 0o644))

	req := httptest.NewRequest(http.MethodPost, "/api/transfers", nil)
	req.Header.Set("Authorization", "Bearer "+signTransferTestToken(t, transferTestUUID))
	req.Header.Set("X-Storage-Pool", "shared")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)

	// Without Docker the environment cannot be created, so the transfer fails;
	// with Docker it succeeds. Either way the data must still be there.
	b, err := os.ReadFile(live)
	require.NoError(t, err, "a pooled transfer (status %d) deleted the source's data", w.Code)
	assert.Equal(t, "live data", string(b))
}

// A non-pooled transfer is refused when the server's files already exist on this
// node, and those files are not touched.
func TestTransferRefusedWhenDataDirectoryExists(t *testing.T) {
	panel := &transferTestPanel{}
	h := newTransferHarness(t, panel)
	dataDir := filepath.Join(config.Get().System.Data, transferTestUUID)
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	existing := filepath.Join(dataDir, "existing.txt")
	require.NoError(t, os.WriteFile(existing, []byte("keep"), 0o644))

	archive := buildTransferTestArchive(t, map[string]string{"received.txt": "data"})
	body, contentType := transferTestMultipart(t, archive, strings.Repeat("0", 64))
	w := h.postTransfer(body, contentType, signTransferTestToken(t, transferTestUUID))

	require.Equal(t, http.StatusConflict, w.Code)
	b, err := os.ReadFile(existing)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(b))
	_, err = os.Stat(filepath.Join(dataDir, "received.txt"))
	assert.True(t, os.IsNotExist(err))
	assert.Empty(t, panel.statuses)
}

// A request for a server whose earlier transfer is still claimed (running, or
// being cleaned up) is refused.
func TestTransferRefusedWhileClaimed(t *testing.T) {
	h := newTransferHarness(t, &transferTestPanel{})
	require.True(t, incomingClaims.claim(transferTestUUID))
	t.Cleanup(func() { incomingClaims.release(transferTestUUID) })

	archive := buildTransferTestArchive(t, map[string]string{"received.txt": "data"})
	body, contentType := transferTestMultipart(t, archive, strings.Repeat("0", 64))
	w := h.postTransfer(body, contentType, signTransferTestToken(t, transferTestUUID))

	require.Equal(t, http.StatusConflict, w.Code)
	_, err := os.Stat(filepath.Join(config.Get().System.Data, transferTestUUID))
	assert.True(t, os.IsNotExist(err))
}

// A failed transfer removes the backups it received but keeps a backup that was
// already on this node, unchanged.
func TestFailedTransferRemovesOnlyReceivedBackups(t *testing.T) {
	h := newTransferHarness(t, &transferTestPanel{})
	cfg := config.Get()
	cfg.System.Transfers.PerformChecksumChecks = true
	config.Set(cfg)

	backupDir := filepath.Join(cfg.System.BackupDirectory, transferTestUUID)
	require.NoError(t, os.MkdirAll(backupDir, 0o700))
	const existingID = "0b6f3c7e-5d0a-4b8e-9f1c-2a3b4c5d6e7f"
	const newID = "7e1d2c3b-4a59-4687-8f9e-0a1b2c3d4e5f"
	existing := filepath.Join(backupDir, existingID+".tar.gz")
	require.NoError(t, os.WriteFile(existing, []byte("original"), 0o600))

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, id := range []string{existingID, newID} {
		part, err := mw.CreateFormFile("backup_"+id+".tar.gz", id+".tar.gz")
		require.NoError(t, err)
		_, err = part.Write([]byte("received"))
		require.NoError(t, err)
	}
	part, err := mw.CreateFormFile("archive", "archive.tar.gz")
	require.NoError(t, err)
	_, err = part.Write(buildTransferTestArchive(t, map[string]string{"received.txt": "data"}))
	require.NoError(t, err)
	// A wrong archive checksum makes the transfer fail after the backups arrived.
	require.NoError(t, mw.WriteField("checksum", strings.Repeat("0", 64)))
	require.NoError(t, mw.Close())

	w := h.postTransfer(&buf, mw.FormDataContentType(), signTransferTestToken(t, transferTestUUID))
	require.NotEqual(t, http.StatusAccepted, w.Code)

	b, err := os.ReadFile(existing)
	require.NoError(t, err, "a backup that was already on the node was removed")
	assert.Equal(t, "original", string(b), "a backup that was already on the node was overwritten")
	_, err = os.Stat(filepath.Join(backupDir, newID+".tar.gz"))
	assert.True(t, os.IsNotExist(err), "a backup received by the failed transfer is still on disk")
	entries, err := os.ReadDir(backupDir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".transfer-"), "temporary backup file %s left behind", e.Name())
	}
	_, err = os.Stat(filepath.Join(cfg.System.Data, transferTestUUID))
	assert.True(t, os.IsNotExist(err))
}

// Received backups are stored like backups created on this node: 0600 files in
// a 0700 directory.
func TestReceivedBackupsArePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backups")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	tmp, sum, err := stageReceivedBackup(dir, "a.tar.gz", strings.NewReader("data"))
	require.NoError(t, err)
	assert.Len(t, sum, 64)
	final := filepath.Join(dir, "a.tar.gz")
	created, err := commitReceivedBackups(map[string]string{final: tmp})
	require.NoError(t, err)
	assert.Equal(t, []string{final}, created)

	st, err := os.Stat(final)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	_, err = os.Stat(tmp)
	assert.True(t, os.IsNotExist(err))

	// Replacing a backup that already exists does not report it as created.
	tmp2, _, err := stageReceivedBackup(dir, "a.tar.gz", strings.NewReader("data"))
	require.NoError(t, err)
	created, err = commitReceivedBackups(map[string]string{final: tmp2})
	require.NoError(t, err)
	assert.Empty(t, created)
}
