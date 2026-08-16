package collab

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/zeebo/blake3"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

const reconcileInterval = time.Second

// HistoryRecorder receives successful collaborative file saves.
type HistoryRecorder interface {
	RecordEdit(path string, before, after []byte, userUUID string) (int64, error)
	Enabled() bool
	FileSizeCap() uint64
}

// Manager hosts collaborative editing sessions for one game server.
type Manager struct {
	serverUUID string
	fs         *filesystem.Filesystem
	ctx        context.Context
	log        *log.Entry
	history    HistoryRecorder

	mu       sync.Mutex
	senders  map[uuid.UUID]Sender
	sessions map[string]*session

	connMu      sync.Mutex
	connections map[uuid.UUID]*connectionState

	pendingMu      sync.Mutex
	pendingUpdates map[pendingKey][]byte

	teardownMu sync.Mutex
	teardowns  map[string]context.CancelFunc
}

type pendingKey struct {
	Connection uuid.UUID
	Editor     string
	Path       string
}

type connectionState struct {
	// path key -> editor ids
	subscriptions map[string]map[string]struct{}
	// raw client path -> resolved key
	keys map[string]string
}

func NewManager(serverUUID string, fs *filesystem.Filesystem, ctx context.Context, logger *log.Entry, history HistoryRecorder) *Manager {
	return &Manager{
		serverUUID:     serverUUID,
		fs:             fs,
		ctx:            ctx,
		log:            logger,
		history:        history,
		senders:        make(map[uuid.UUID]Sender),
		sessions:       make(map[string]*session),
		connections:    make(map[uuid.UUID]*connectionState),
		pendingUpdates: make(map[pendingKey][]byte),
		teardowns:      make(map[string]context.CancelFunc),
	}
}

func (m *Manager) cfg() config.FileCollaboration {
	return config.Get().System.FileCollaboration
}

// Register attaches a websocket sender for a connection.
func (m *Manager) Register(connectionID uuid.UUID, sender Sender) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.senders[connectionID] = sender
}

// Disconnect removes a connection and leaves all of its collab sessions.
func (m *Manager) Disconnect(connectionID uuid.UUID) {
	m.connMu.Lock()
	conn := m.connections[connectionID]
	delete(m.connections, connectionID)
	m.connMu.Unlock()

	m.pendingMu.Lock()
	for k := range m.pendingUpdates {
		if k.Connection == connectionID {
			delete(m.pendingUpdates, k)
		}
	}
	m.pendingMu.Unlock()

	m.mu.Lock()
	delete(m.senders, connectionID)
	m.mu.Unlock()

	if conn == nil {
		return
	}
	for key := range conn.subscriptions {
		m.leaveSession(connectionID, key)
	}
}

func normalizePath(raw string) string {
	p := strings.TrimSpace(raw)
	p = strings.TrimLeft(p, "/")
	p = path.Clean("/" + p)
	return strings.TrimLeft(p, "/")
}

func editorID(editor string) (string, error) {
	if editor == "" {
		return "", nil
	}
	if len(editor) > maxEditorIDLen {
		return "", ErrEditorIDTooLong
	}
	return editor, nil
}

func (m *Manager) resolve(raw string) (key string, filePath string, err error) {
	if !m.cfg().Enabled {
		return "", "", ErrDisabled
	}
	key = normalizePath(raw)
	if key == "" || key == "." {
		return "", "", ErrInvalidFileName
	}
	if path.Base(key) == "." || path.Base(key) == ".." {
		return "", "", ErrInvalidFileName
	}
	filePath = "/" + key
	if err := m.fs.IsIgnored(filePath); err != nil {
		return "", "", ErrFileNotFound
	}
	return key, filePath, nil
}

func (m *Manager) readContent(filePath string, sizeCap int64) (string, error) {
	f, st, err := m.fs.File(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrFileNotFound
		}
		if strings.Contains(err.Error(), "is a directory") {
			return "", ErrNotAFile
		}
		return "", err
	}
	defer f.Close()

	if st.Size() > sizeCap {
		return "", ErrTooLarge
	}
	buf := make([]byte, st.Size())
	if _, err := io.ReadFull(f, buf); err != nil {
		return "", err
	}
	if !utf8Valid(buf) {
		return "", ErrNotEditable
	}
	return string(buf), nil
}

func utf8Valid(b []byte) bool {
	return strings.ToValidUTF8(string(b), "") == string(b)
}

func (m *Manager) sendTo(connectionID uuid.UUID, msg Message) {
	m.mu.Lock()
	sender := m.senders[connectionID]
	m.mu.Unlock()
	if sender != nil {
		sender(msg)
	}
}

func (m *Manager) broadcast(session *session, except *uuid.UUID, msg Message) {
	session.participantsMu.Lock()
	ids := make([]uuid.UUID, 0, len(session.participants))
	for id := range session.participants {
		if except != nil && id == *except {
			continue
		}
		ids = append(ids, id)
	}
	session.participantsMu.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if sender := m.senders[id]; sender != nil {
			sender(msg)
		}
	}
}

// Subscribe joins a collaborative editing session for a file.
func (m *Manager) Subscribe(connectionID uuid.UUID, userUUID, userName string, avatar *string, rawPath, editor string) error {
	ed, err := editorID(editor)
	if err != nil {
		return err
	}
	key, filePath, err := m.resolve(rawPath)
	if err != nil {
		return err
	}

	cfg := m.cfg()
	sizeCap := int64(cfg.FileSizeCap)
	maxSessions := int(cfg.MaxSessionsPerServer)
	maxSubs := int(cfg.MaxSessionsPerConnection)
	maxEditors := int(cfg.MaxEditorsPerSession)

	m.connMu.Lock()
	conn := m.connections[connectionID]
	if conn == nil {
		conn = &connectionState{
			subscriptions: make(map[string]map[string]struct{}),
			keys:          make(map[string]string),
		}
		m.connections[connectionID] = conn
	}
	if _, ok := conn.subscriptions[key]; !ok && len(conn.subscriptions) >= maxSubs {
		m.connMu.Unlock()
		return ErrTooManyConnSubs
	}
	editors := conn.subscriptions[key]
	if editors != nil {
		if _, ok := editors[ed]; !ok && len(editors) >= maxEditors {
			m.connMu.Unlock()
			return ErrTooManyEditors
		}
	}
	m.connMu.Unlock()

	m.cancelTeardown(key)

	m.mu.Lock()
	sess := m.sessions[key]
	if sess == nil {
		if len(m.sessions) >= maxSessions {
			m.mu.Unlock()
			return ErrTooManySessions
		}
		content, err := m.readContent(filePath, sizeCap)
		if err != nil {
			m.mu.Unlock()
			return err
		}
		sess = newSession(key, filePath, content)
		m.sessions[key] = sess
		m.mu.Unlock()
		m.spawnReconciler(sess)
		m.log.WithField("path", key).Debug("opened collaborative editing session")
	} else {
		m.mu.Unlock()
		sess.participantsMu.Lock()
		empty := len(sess.participants) == 0
		sess.participantsMu.Unlock()
		if empty && !sess.dirty.Load() {
			content, err := m.readContent(filePath, sizeCap)
			if err != nil {
				return err
			}
			if sess.doc.diskHashCopy() != contentHash(content) {
				sess.doc.replace(content)
			}
			sess.setConflict(nil)
			sess.awarenessMu.Lock()
			sess.awareness = make(map[uuid.UUID]map[uint64]uint64)
			sess.awarenessMu.Unlock()
		}
	}

	sess.participantsMu.Lock()
	sess.participants[connectionID] = sessionParticipant{
		UserUUID: userUUID,
		UserName: userName,
		Avatar:   avatar,
	}
	sess.participantsMu.Unlock()

	m.connMu.Lock()
	conn = m.connections[connectionID]
	if conn.subscriptions[key] == nil {
		conn.subscriptions[key] = make(map[string]struct{})
	}
	conn.subscriptions[key][ed] = struct{}{}
	conn.keys[normalizePath(rawPath)] = key
	m.connMu.Unlock()

	state := sess.doc.encodeFullState()
	meta := SyncMeta{
		Dirty: sess.dirty.Load(),
	}
	if c := sess.currentConflict(); c != nil {
		cc := c.toConflict()
		meta.Conflict = &cc
	}

	m.sendTo(connectionID, Message{
		Event: EventSync,
		Args: []string{
			key,
			base64.StdEncoding.EncodeToString(state),
			mustJSON(meta),
		},
	})
	m.broadcast(sess, nil, sess.participantsMessage())
	return nil
}

// Unsubscribe leaves a collaborative editing session.
func (m *Manager) Unsubscribe(connectionID uuid.UUID, rawPath, editor string) error {
	ed, err := editorID(editor)
	if err != nil {
		return err
	}
	key, _, resolveErr := m.resolve(rawPath)
	normalized := normalizePath(rawPath)

	m.connMu.Lock()
	conn := m.connections[connectionID]
	if conn == nil {
		m.connMu.Unlock()
		return nil
	}
	resolved := conn.keys[normalized]
	if resolved == "" && resolveErr == nil {
		resolved = key
	}
	if resolved == "" {
		m.connMu.Unlock()
		return nil
	}
	editors := conn.subscriptions[resolved]
	if editors == nil {
		m.connMu.Unlock()
		return nil
	}
	delete(editors, ed)
	last := len(editors) == 0
	if last {
		delete(conn.subscriptions, resolved)
		for raw, k := range conn.keys {
			if k == resolved {
				delete(conn.keys, raw)
			}
		}
	}
	if len(conn.subscriptions) == 0 {
		delete(m.connections, connectionID)
	}
	m.connMu.Unlock()

	m.pendingMu.Lock()
	delete(m.pendingUpdates, pendingKey{Connection: connectionID, Editor: ed, Path: resolved})
	m.pendingMu.Unlock()

	if last {
		m.leaveSession(connectionID, resolved)
	}
	return nil
}

func (m *Manager) leaveSession(connectionID uuid.UUID, key string) {
	m.mu.Lock()
	sess := m.sessions[key]
	m.mu.Unlock()
	if sess == nil {
		return
	}

	sess.participantsMu.Lock()
	delete(sess.participants, connectionID)
	empty := len(sess.participants) == 0
	sess.participantsMu.Unlock()

	removal := sess.awarenessRemovalMessage(connectionID)
	if empty {
		m.scheduleTeardown(key)
		return
	}
	if removal != nil {
		m.broadcast(sess, nil, *removal)
	}
	m.broadcast(sess, nil, sess.participantsMessage())
}

func (m *Manager) subscribedSession(connectionID uuid.UUID, rawPath string) (*session, error) {
	key, _, err := m.resolve(rawPath)
	if err != nil {
		return nil, err
	}

	m.connMu.Lock()
	conn := m.connections[connectionID]
	subscribed := conn != nil && conn.subscriptions[key] != nil
	m.connMu.Unlock()
	if !subscribed {
		return nil, ErrNotSubscribed
	}

	m.mu.Lock()
	sess := m.sessions[key]
	m.mu.Unlock()
	if sess == nil {
		return nil, ErrNotSubscribed
	}
	return sess, nil
}

// ApplyUpdate applies a (possibly chunked) Yjs update from a client.
func (m *Manager) ApplyUpdate(connectionID uuid.UUID, rawPath string, finished bool, chunk, editor string) error {
	ed, err := editorID(editor)
	if err != nil {
		return err
	}
	sess, err := m.subscribedSession(connectionID, rawPath)
	if err != nil {
		return err
	}

	sizeCap := m.cfg().FileSizeCap
	decodedChunk, err := base64.StdEncoding.DecodeString(chunk)
	if err != nil {
		return ErrInvalidUpdate
	}

	pk := pendingKey{Connection: connectionID, Editor: ed, Path: sess.key}
	m.pendingMu.Lock()
	buf := m.pendingUpdates[pk]
	if buf != nil {
		if uint64(len(buf)+len(decodedChunk)) > sizeCap {
			delete(m.pendingUpdates, pk)
			m.pendingMu.Unlock()
			return ErrTooLarge
		}
		buf = append(buf, decodedChunk...)
		if !finished {
			m.pendingUpdates[pk] = buf
			m.pendingMu.Unlock()
			return nil
		}
		delete(m.pendingUpdates, pk)
		m.pendingMu.Unlock()
	} else {
		if uint64(len(decodedChunk)) > sizeCap {
			m.pendingMu.Unlock()
			return ErrTooLarge
		}
		if !finished {
			m.pendingUpdates[pk] = decodedChunk
			m.pendingMu.Unlock()
			return nil
		}
		m.pendingMu.Unlock()
		buf = decodedChunk
	}

	if err := sess.doc.applyUpdate(buf); err != nil {
		return ErrInvalidUpdate
	}
	sess.dirty.Store(true)

	needsResync := false
	if sess.doc.length() > sizeCap {
		sess.doc.truncateToCap(sizeCap)
		needsResync = true
	} else {
		applied := sess.doc.addAppliedBytes(uint64(len(buf)))
		if applied > sizeCap*8 {
			content := sess.doc.content()
			sess.doc.replace(content)
			needsResync = true
		}
	}

	if needsResync {
		m.broadcast(sess, nil, Message{
			Event: EventError,
			Args:  []string{sess.key, "resync"},
		})
		return nil
	}

	except := connectionID
	m.broadcast(sess, &except, Message{
		Event: EventUpdate,
		Args: []string{
			sess.key,
			base64.StdEncoding.EncodeToString(buf),
		},
	})
	return nil
}

// RelayAwareness relays cursor/presence awareness to other editors.
func (m *Manager) RelayAwareness(connectionID uuid.UUID, rawPath, payload string) error {
	sess, err := m.subscribedSession(connectionID, rawPath)
	if err != nil {
		return err
	}

	if raw, err := base64.StdEncoding.DecodeString(payload); err == nil {
		if entries, ok := decodeAwareness(raw); ok {
			sess.trackAwareness(connectionID, entries, int(m.cfg().MaxCursorsPerConnection))
		}
	}

	except := connectionID
	m.broadcast(sess, &except, Message{
		Event: EventAwareness,
		Args:  []string{sess.key, payload},
	})
	return nil
}

// Save writes the collaborative document to disk.
func (m *Manager) Save(connectionID uuid.UUID, userUUID, rawPath string, force bool, expectedHash string) error {
	sess, err := m.subscribedSession(connectionID, rawPath)
	if err != nil {
		return err
	}
	_, filePath, err := m.resolve(rawPath)
	if err != nil {
		return err
	}

	sess.saveMu.Lock()
	defer sess.saveMu.Unlock()

	content := sess.doc.content()
	docDiskHash := sess.doc.diskHashCopy()
	sizeCap := int64(m.cfg().FileSizeCap)

	var (
		fileExists     bool
		oldContentSize int64
		oldBytes       []byte
	)

	st, err := m.fs.Stat(filePath)
	switch {
	case err == nil && !st.IsDir():
		fileExists = true
		oldContentSize = st.Size()
	case err == nil && st.IsDir():
		return ErrNotAFile
	case os.IsNotExist(err):
		fileExists = false
	default:
		if strings.Contains(err.Error(), "not exist") {
			fileExists = false
		} else {
			return err
		}
	}

	if fileExists && oldContentSize > 0 && oldContentSize <= sizeCap {
		if f, _, openErr := m.fs.File(filePath); openErr == nil {
			buf := make([]byte, oldContentSize)
			_, _ = io.ReadFull(f, buf)
			_ = f.Close()
			oldBytes = buf
		}
	}

	var currentHash *[32]byte
	if !fileExists {
		currentHash = nil
	} else if oldContentSize == 0 {
		h := blake3.Sum256(nil)
		currentHash = &h
	} else if oldBytes != nil {
		h := blake3.Sum256(oldBytes)
		currentHash = &h
	}

	matches := currentHash != nil && *currentHash == docDiskHash
	if !matches {
		forceApplies := force
		if forceApplies && expectedHash != "" {
			forceApplies = currentHash != nil && hex.EncodeToString(currentHash[:]) == expectedHash
		}
		if !forceApplies {
			state := &conflictState{Hash: currentHash, Deleted: !fileExists}
			sess.setConflict(state)
			m.broadcast(sess, nil, sess.conflictMessage(state))
			return nil
		}
	}

	delta := int64(len(content)) - oldContentSize
	if delta > 0 {
		if err := m.fs.HasSpaceFor(delta); err != nil {
			return ErrAllocateSpace
		}
	}

	if err := m.fs.Write(filePath, strings.NewReader(content), int64(len(content)), 0o644); err != nil {
		return err
	}

	newHash := contentHash(content)
	sess.doc.setDiskHash(newHash)
	sess.dirty.Store(sess.doc.content() != content)
	sess.setConflict(nil)

	saved := Saved{User: userUUID}
	if m.history != nil && m.history.Enabled() && uint64(len(content)) <= m.history.FileSizeCap() &&
		(!fileExists || uint64(oldContentSize) <= m.history.FileSizeCap()) {
		if revisionID, historyErr := m.history.RecordEdit(sess.key, oldBytes, []byte(content), userUUID); historyErr != nil {
			m.log.WithError(historyErr).WithField("path", sess.key).Warn("collab: failed to record file revision")
		} else if revisionID != 0 {
			saved.RevisionID = &revisionID
		}
	}
	m.broadcast(sess, nil, Message{
		Event: EventSaved,
		Args:  []string{sess.key, mustJSON(saved)},
	})
	return nil
}

// Reload reloads session content from disk and forces clients to resync.
func (m *Manager) Reload(connectionID uuid.UUID, rawPath string) error {
	sess, err := m.subscribedSession(connectionID, rawPath)
	if err != nil {
		return err
	}

	sess.saveMu.Lock()
	defer sess.saveMu.Unlock()

	content, err := m.readContent(sess.path, int64(m.cfg().FileSizeCap))
	if err != nil {
		return err
	}
	sess.doc.replace(content)
	sess.dirty.Store(false)
	sess.setConflict(nil)

	m.broadcast(sess, nil, Message{
		Event: EventError,
		Args:  []string{sess.key, "resync"},
	})
	return nil
}

func (m *Manager) spawnReconciler(sess *session) {
	go func() {
		var lastMtime time.Time
		reportedUnreadable := false
		ticker := time.NewTicker(reconcileInterval)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
			}

			m.mu.Lock()
			current := m.sessions[sess.key]
			m.mu.Unlock()
			if current != sess {
				return
			}

			if !sess.saveMu.TryLock() {
				continue
			}

			sizeCap := int64(m.cfg().FileSizeCap)
			if sess.dirty.Load() {
				if contentHash(sess.doc.content()) == sess.doc.diskHashCopy() {
					sess.dirty.Store(false)
				}
			}

			st, err := m.fs.Stat(sess.path)
			if err != nil || st.IsDir() {
				deleted := true
				if err == nil && st.IsDir() {
					deleted = false
				}
				if sess.dirty.Load() {
					state := &conflictState{Deleted: deleted}
					if sess.setConflict(state) {
						m.broadcast(sess, nil, sess.conflictMessage(state))
					}
				} else if !reportedUnreadable {
					reportedUnreadable = true
					m.broadcast(sess, nil, Message{Event: EventError, Args: []string{sess.key, "resync"}})
				}
				sess.saveMu.Unlock()
				continue
			}

			if st.Size() > sizeCap {
				if sess.dirty.Load() {
					state := &conflictState{Deleted: false}
					if sess.setConflict(state) {
						m.broadcast(sess, nil, sess.conflictMessage(state))
					}
				}
				sess.saveMu.Unlock()
				continue
			}

			mtime := st.ModTime()
			if !lastMtime.IsZero() && mtime.Equal(lastMtime) {
				sess.saveMu.Unlock()
				continue
			}

			content, readErr := m.readContent(sess.path, sizeCap)
			if readErr != nil {
				if sess.dirty.Load() {
					state := &conflictState{Deleted: true}
					if sess.setConflict(state) {
						m.broadcast(sess, nil, sess.conflictMessage(state))
					}
				} else if !reportedUnreadable {
					reportedUnreadable = true
					m.broadcast(sess, nil, Message{Event: EventError, Args: []string{sess.key, "resync"}})
				}
				sess.saveMu.Unlock()
				continue
			}
			lastMtime = mtime
			reportedUnreadable = false

			diskH := contentHash(content)
			if sess.doc.diskHashCopy() == diskH {
				if sess.setConflict(nil) {
					m.broadcast(sess, nil, sess.conflictMessage(nil))
				}
				sess.saveMu.Unlock()
				continue
			}

			if sess.dirty.Load() {
				h := diskH
				state := &conflictState{Hash: &h, Deleted: false}
				if sess.setConflict(state) {
					m.log.WithField("path", sess.key).Debug("collab: file changed on disk while session has unsaved changes")
					m.broadcast(sess, nil, sess.conflictMessage(state))
				}
			} else {
				sess.doc.replace(content)
				sess.setConflict(nil)
				m.log.WithField("path", sess.key).Debug("collab: reloaded clean session from external file change")
				m.broadcast(sess, nil, Message{Event: EventError, Args: []string{sess.key, "resync"}})
			}
			sess.saveMu.Unlock()
		}
	}()
}

func (m *Manager) scheduleTeardown(key string) {
	grace := time.Duration(m.cfg().SessionGracePeriod) * time.Second
	if grace <= 0 {
		grace = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(m.ctx)
	m.teardownMu.Lock()
	if old, ok := m.teardowns[key]; ok {
		old()
	}
	m.teardowns[key] = cancel
	m.teardownMu.Unlock()

	go func() {
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		m.mu.Lock()
		sess := m.sessions[key]
		if sess != nil {
			sess.participantsMu.Lock()
			empty := len(sess.participants) == 0
			sess.participantsMu.Unlock()
			if empty {
				if sess.dirty.Load() {
					m.log.WithField("path", key).Warn("discarding collaborative editing session with unsaved changes")
				}
				delete(m.sessions, key)
			}
		}
		m.mu.Unlock()

		m.teardownMu.Lock()
		delete(m.teardowns, key)
		m.teardownMu.Unlock()
	}()
}

func (m *Manager) cancelTeardown(key string) {
	m.teardownMu.Lock()
	if cancel, ok := m.teardowns[key]; ok {
		cancel()
		delete(m.teardowns, key)
	}
	m.teardownMu.Unlock()
}

// UserError returns true when err is a client-facing collab error.
func UserError(err error) bool {
	switch err {
	case ErrDisabled, ErrNotSubscribed, ErrFileNotFound, ErrNotAFile, ErrNotEditable,
		ErrTooLarge, ErrInvalidUpdate, ErrTooManySessions, ErrTooManyConnSubs,
		ErrTooManyEditors, ErrEditorIDTooLong, ErrNoParent, ErrInvalidFileName,
		ErrAllocateSpace, ErrMissingPermission:
		return true
	default:
		return false
	}
}
