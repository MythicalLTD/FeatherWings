package collab

func decodeAwareness(update []byte) ([]awarenessEntry, bool) {
	count, offset, ok := readVarUint(update, 0)
	if !ok {
		return nil, false
	}
	entries := make([]awarenessEntry, 0, min(int(count), 64))
	for i := uint64(0); i < count; i++ {
		client, next, ok := readVarUint(update, offset)
		if !ok {
			return nil, false
		}
		clock, next, ok := readVarUint(update, next)
		if !ok {
			return nil, false
		}
		state, next, ok := readBuf(update, next)
		if !ok {
			return nil, false
		}
		entries = append(entries, awarenessEntry{
			client:  client,
			clock:   clock,
			removed: string(state) == "null",
		})
		offset = next
	}
	return entries, true
}

func encodeAwarenessRemoval(clients map[uint64]uint64) []byte {
	out := writeVarUint(nil, uint64(len(clients)))
	for client, clock := range clients {
		out = writeVarUint(out, client)
		out = writeVarUint(out, clock)
		out = writeBuf(out, []byte("null"))
	}
	return out
}

func trackAwarenessClients(clients map[uint64]uint64, entries []awarenessEntry, maxCursors int) {
	for _, entry := range entries {
		if entry.client > maxAwarenessInt || entry.clock > maxAwarenessInt {
			continue
		}
		if entry.removed {
			if existing, ok := clients[entry.client]; ok && existing < entry.clock {
				delete(clients, entry.client)
			}
			continue
		}
		if existing, ok := clients[entry.client]; ok && existing >= entry.clock {
			continue
		}
		if _, ok := clients[entry.client]; !ok && len(clients) >= maxCursors {
			continue
		}
		clients[entry.client] = entry.clock
	}
}

type awarenessEntry struct {
	client  uint64
	clock   uint64
	removed bool
}

const maxAwarenessInt = (1 << 53) - 1

func readVarUint(buf []byte, offset int) (uint64, int, bool) {
	var value uint64
	var shift uint
	for offset < len(buf) {
		b := buf[offset]
		offset++
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, offset, true
		}
		shift += 7
		if shift > 63 {
			return 0, offset, false
		}
	}
	return 0, offset, false
}

func writeVarUint(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

func readBuf(buf []byte, offset int) ([]byte, int, bool) {
	length, offset, ok := readVarUint(buf, offset)
	if !ok || length > uint64(len(buf)-offset) {
		return nil, offset, false
	}
	end := offset + int(length)
	return buf[offset:end], end, true
}

func writeBuf(dst []byte, data []byte) []byte {
	dst = writeVarUint(dst, uint64(len(data)))
	return append(dst, data...)
}
