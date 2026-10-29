package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// dropboxHashBlock is the block size Dropbox uses for its content_hash.
const dropboxHashBlock = 4 * 1024 * 1024

// DropboxContentHash computes Dropbox's content_hash: the SHA-256 of the
// concatenated SHA-256 digests of every 4 MiB block of the file.
// See https://www.dropbox.com/developers/reference/content-hash
func DropboxContentHash(r io.Reader) (string, error) {
	outer := sha256.New()
	buf := make([]byte, dropboxHashBlock)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			sum := sha256.Sum256(buf[:n])
			outer.Write(sum[:])
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
}
