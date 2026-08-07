package collab

import (
	"sync"
	"unicode/utf8"

	"github.com/Deln0r/ygo"
	"github.com/zeebo/blake3"
)

const yTextName = "content"

// collabDoc wraps a Yjs document holding collaborative file content.
type collabDoc struct {
	mu                 sync.Mutex
	doc                *ygo.Doc
	text               *ygo.Text
	appliedUpdateBytes uint64
	diskHash           [32]byte
}

func newCollabDoc(content string) *collabDoc {
	doc := ygo.NewDoc()
	text := ygo.NewText(doc, yTextName)
	txn := doc.WriteTxn()
	_ = text.Insert(txn, 0, content)
	txn.Commit()

	return &collabDoc{
		doc:      doc,
		text:     text,
		diskHash: blake3.Sum256([]byte(content)),
	}
}

func (d *collabDoc) encodeFullState() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return ygo.EncodeStateAsUpdate(d.doc)
}

func (d *collabDoc) content() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.text.String()
}

func (d *collabDoc) applyUpdate(update []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return ygo.ApplyUpdate(d.doc, update)
}

func (d *collabDoc) length() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.text.Length()
}

func (d *collabDoc) diskHashCopy() [32]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.diskHash
}

func (d *collabDoc) setDiskHash(h [32]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.diskHash = h
}

func (d *collabDoc) replace(content string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	doc := ygo.NewDoc()
	text := ygo.NewText(doc, yTextName)
	txn := doc.WriteTxn()
	_ = text.Insert(txn, 0, content)
	txn.Commit()
	d.doc = doc
	d.text = text
	d.appliedUpdateBytes = 0
	d.diskHash = blake3.Sum256([]byte(content))
}

func (d *collabDoc) truncateToCap(sizeCap uint64) {
	content := d.content()
	capBytes := int(sizeCap)
	if capBytes >= len(content) {
		return
	}
	for capBytes > 0 && !utf8.RuneStart(content[capBytes]) {
		capBytes--
	}
	d.replace(content[:capBytes])
}

func (d *collabDoc) addAppliedBytes(n uint64) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.appliedUpdateBytes += n
	return d.appliedUpdateBytes
}
