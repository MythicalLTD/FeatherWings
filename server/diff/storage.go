package diff

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/zeebo/blake3"
)

const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS files (
    id   INTEGER PRIMARY KEY,
    path TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS revisions (
    id           INTEGER PRIMARY KEY,
    file_id      INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    chain_id     INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    user_id      BLOB,
    base_id      INTEGER,
    payload      BLOB NOT NULL,
    content_hash BLOB NOT NULL,
    created      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS revisions_file_id_id ON revisions(file_id, id DESC);
CREATE INDEX IF NOT EXISTS revisions_created ON revisions(created, id);
`

type storage struct {
	db      *sql.DB
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

func openStorage(databasePath string, level int) (*storage, error) {
	db, err := sql.Open("sqlite", databasePath+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if _, err = db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize file history database: %w", err)
	}

	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize zstd encoder: %w", err)
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		encoder.Close()
		_ = db.Close()
		return nil, fmt.Errorf("initialize zstd decoder: %w", err)
	}

	return &storage{db: db, encoder: encoder, decoder: decoder}, nil
}

func (s *storage) close() error {
	s.encoder.Close()
	s.decoder.Close()
	return s.db.Close()
}

func (s *storage) fileID(tx *sql.Tx, filePath string) (int64, error) {
	if _, err := tx.Exec(`INSERT INTO files(path) VALUES (?) ON CONFLICT(path) DO NOTHING`, filePath); err != nil {
		return 0, err
	}
	var id int64
	if err := tx.QueryRow(`SELECT id FROM files WHERE path = ?`, filePath).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *storage) insertSnapshot(filePath string, content []byte, userUUID string, keepChains, perFileBudget, perServerBudget uint64) (int64, error) {
	payload := s.encoder.EncodeAll(content, nil)
	hash := blake3.Sum256(content)

	var user any
	if parsed, err := uuid.Parse(userUUID); err == nil {
		b, _ := parsed.MarshalBinary()
		user = b
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	fileID, err := s.fileID(tx, filePath)
	if err != nil {
		return 0, err
	}

	result, err := tx.Exec(
		`INSERT INTO revisions(file_id, chain_id, size, user_id, base_id, payload, content_hash, created)
		 VALUES (?, 0, ?, ?, NULL, ?, ?, ?)`,
		fileID, len(content), user, payload, hash[:], time.Now().UTC().UnixMilli(),
	)
	if err != nil {
		return 0, err
	}
	revisionID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`UPDATE revisions SET chain_id = ? WHERE id = ?`, revisionID, revisionID); err != nil {
		return 0, err
	}

	if err := pruneFile(tx, fileID, revisionID, keepChains, perFileBudget); err != nil {
		return 0, err
	}
	if err := pruneServer(tx, revisionID, perServerBudget); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`DELETE FROM files WHERE NOT EXISTS (SELECT 1 FROM revisions WHERE revisions.file_id = files.id)`); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revisionID, nil
}

func pruneFile(tx *sql.Tx, fileID, protectedRevisionID int64, keepChains, budget uint64) error {
	if keepChains > 0 {
		_, err := tx.Exec(
			`DELETE FROM revisions WHERE file_id = ? AND id NOT IN
			 (SELECT id FROM revisions WHERE file_id = ? ORDER BY id DESC LIMIT ?)`,
			fileID, fileID, boundedInt64(keepChains),
		)
		if err != nil {
			return err
		}
	}
	for {
		var total int64
		if err := tx.QueryRow(`SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM revisions WHERE file_id = ?`, fileID).Scan(&total); err != nil {
			return err
		}
		if total <= boundedInt64(budget) {
			break
		}
		result, err := tx.Exec(
			`DELETE FROM revisions WHERE id = (SELECT id FROM revisions WHERE file_id = ? AND id <> ? ORDER BY id LIMIT 1)`,
			fileID, protectedRevisionID,
		)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			break
		}
	}
	return nil
}

func pruneServer(tx *sql.Tx, protectedRevisionID int64, budget uint64) error {
	for {
		var total int64
		if err := tx.QueryRow(`SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM revisions`).Scan(&total); err != nil {
			return err
		}
		if total <= boundedInt64(budget) {
			return nil
		}
		result, err := tx.Exec(
			`DELETE FROM revisions WHERE id = (
				SELECT r.id FROM revisions r
				WHERE r.id <> ?
				  AND (SELECT COUNT(*) FROM revisions own WHERE own.file_id = r.file_id) > 1
				ORDER BY r.created, r.id LIMIT 1
			)`,
			protectedRevisionID,
		)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			return nil
		}
	}
}

func boundedInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

func (s *storage) latestRevision(filePath string) (int64, []byte, error) {
	var (
		id   int64
		hash []byte
	)
	err := s.db.QueryRow(
		`SELECT r.id, r.content_hash FROM revisions r JOIN files f ON f.id = r.file_id
		 WHERE f.path = ? ORDER BY r.id DESC LIMIT 1`, filePath,
	).Scan(&id, &hash)
	return id, hash, err
}

func (s *storage) list(filePath string) ([]RevisionInfo, error) {
	rows, err := s.db.Query(
		`SELECT r.id, r.size, LENGTH(r.payload), r.user_id, r.base_id, r.created
		 FROM revisions r JOIN files f ON f.id = r.file_id
		 WHERE f.path = ? ORDER BY r.id DESC`, filePath,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	revisions := make([]RevisionInfo, 0)
	for rows.Next() {
		var (
			info    RevisionInfo
			user    []byte
			baseID  sql.NullInt64
			created int64
		)
		if err := rows.Scan(&info.ID, &info.Size, &info.StoredSize, &user, &baseID, &created); err != nil {
			return nil, err
		}
		if len(user) == 16 {
			if parsed, err := uuid.FromBytes(user); err == nil {
				value := parsed.String()
				info.User = &value
			}
		}
		info.IsSnapshot = !baseID.Valid
		info.Created = time.UnixMilli(created).UTC()
		revisions = append(revisions, info)
	}
	return revisions, rows.Err()
}

func (s *storage) reconstruct(revisionID int64) ([]byte, error) {
	var payload []byte
	if err := s.db.QueryRow(`SELECT payload FROM revisions WHERE id = ?`, revisionID).Scan(&payload); err != nil {
		return nil, err
	}
	content, err := s.decoder.DecodeAll(payload, nil)
	if err != nil {
		return nil, fmt.Errorf("decode revision %d: %w", revisionID, err)
	}
	return content, nil
}

func (s *storage) revisionPath(revisionID int64) (string, error) {
	var filePath string
	err := s.db.QueryRow(
		`SELECT f.path FROM revisions r JOIN files f ON f.id = r.file_id WHERE r.id = ?`,
		revisionID,
	).Scan(&filePath)
	return filePath, err
}

func (s *storage) deleteFile(filePath string) error {
	prefix := escapeLike(filePath) + "/%"
	_, err := s.db.Exec(`DELETE FROM files WHERE path = ? OR path LIKE ? ESCAPE '\'`, filePath, prefix)
	return err
}

func (s *storage) renameFile(oldPath, newPath string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	oldPrefix := escapeLike(oldPath) + "/%"
	newPrefix := escapeLike(newPath) + "/%"
	if _, err = tx.Exec(`DELETE FROM files WHERE path = ? OR path LIKE ? ESCAPE '\'`, newPath, newPrefix); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id, path FROM files WHERE path = ? OR path LIKE ? ESCAPE '\' ORDER BY LENGTH(path)`, oldPath, oldPrefix)
	if err != nil {
		return err
	}
	type rename struct {
		id   int64
		path string
	}
	var renames []rename
	for rows.Next() {
		var item rename
		if err := rows.Scan(&item.id, &item.path); err != nil {
			rows.Close()
			return err
		}
		renames = append(renames, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range renames {
		suffix := strings.TrimPrefix(item.path, oldPath)
		if _, err = tx.Exec(`UPDATE files SET path = ? WHERE id = ?`, newPath+suffix, item.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func (s *storage) clear() error {
	_, err := s.db.Exec(`DELETE FROM files`)
	return err
}

func (s *storage) vacuum() error {
	_, err := s.db.Exec(`VACUUM`)
	return err
}

func isNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
