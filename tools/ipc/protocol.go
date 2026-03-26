package ipc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Protocol wire format: [2-byte type BE] [4-byte length BE] [payload]
const (
	TypePing    uint16 = 0x0000
	TypePong    uint16 = 0x0001
	TypeMessage uint16 = 0x0002

	headerSize = 6           // 2 (type) + 4 (length)
	maxPayload = 1024 * 1024 // 1MB max message size
)

// writePacket writes a typed packet to the connection.
// writePacket writes header+payload in a single Write to avoid partial sends.
func writePacket(conn net.Conn, typ uint16, payload []byte) error {
	if len(payload) > maxPayload {
		return fmt.Errorf("payload too large (%d bytes, max %d)", len(payload), maxPayload)
	}
	buf := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint16(buf[0:2], typ)
	binary.BigEndian.PutUint32(buf[2:6], uint32(len(payload)))
	copy(buf[headerSize:], payload)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}
	return nil
}

// readPacket reads a typed packet from the connection.
// Returns (type, payload, error). Respects connection deadlines.
func readPacket(conn net.Conn) (uint16, []byte, error) {
	hdr := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, fmt.Errorf("read header: %w", err)
	}
	typ := binary.BigEndian.Uint16(hdr[0:2])
	length := binary.BigEndian.Uint32(hdr[2:6])

	if length > maxPayload {
		return 0, nil, fmt.Errorf("payload too large (%d bytes, max %d)", length, maxPayload)
	}
	if length == 0 {
		return typ, nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, fmt.Errorf("read payload: %w", err)
	}
	return typ, payload, nil
}

// sendPing sends a PING and waits for PONG with a timeout.
func sendPing(conn net.Conn, timeout time.Duration) error {
	if err := writePacket(conn, TypePing, nil); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	typ, _, err := readPacket(conn)
	if err != nil {
		return fmt.Errorf("waiting for PONG: %w", err)
	}
	if typ != TypePong {
		return fmt.Errorf("expected PONG (0x%04X), got 0x%04X", TypePong, typ)
	}
	return nil
}
