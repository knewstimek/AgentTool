package memtool

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ValueType represents the data type for memory scanning.
type ValueType int

const (
	TypeInt8 ValueType = iota
	TypeInt16
	TypeInt32
	TypeInt64
	TypeUint8
	TypeUint16
	TypeUint32
	TypeUint64
	TypeFloat32
	TypeFloat64
	TypeString
	TypeUTF16
	TypeBytes
)

var valueTypeNames = map[string]ValueType{
	"int8": TypeInt8, "int16": TypeInt16, "int32": TypeInt32, "int64": TypeInt64,
	"uint8": TypeUint8, "uint16": TypeUint16, "uint32": TypeUint32, "uint64": TypeUint64,
	"float32": TypeFloat32, "float64": TypeFloat64,
	"string": TypeString, "utf16": TypeUTF16, "bytes": TypeBytes,
}

func parseValueType(s string) (ValueType, error) {
	vt, ok := valueTypeNames[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("unknown value type %q (supported: int8/16/32/64, uint8/16/32/64, float32/64, string, utf16, bytes)", s)
	}
	return vt, nil
}

// valueSize returns byte size for fixed-size types, 0 for variable-length.
func valueSize(vt ValueType) int {
	switch vt {
	case TypeInt8, TypeUint8:
		return 1
	case TypeInt16, TypeUint16:
		return 2
	case TypeInt32, TypeUint32, TypeFloat32:
		return 4
	case TypeInt64, TypeUint64, TypeFloat64:
		return 8
	default:
		return 0
	}
}

// pointerSize returns the pointer size based on value type alignment hint.
// Default 8 (64-bit). Used by pointer scan.
func pointerSize() int {
	return 8
}

// encodeValue converts a string representation to its binary form.
func encodeValue(vt ValueType, value string, bo binary.ByteOrder) ([]byte, error) {
	switch vt {
	case TypeInt8:
		v, err := strconv.ParseInt(value, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid int8: %w", err)
		}
		return []byte{byte(int8(v))}, nil

	case TypeInt16:
		v, err := strconv.ParseInt(value, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid int16: %w", err)
		}
		buf := make([]byte, 2)
		bo.PutUint16(buf, uint16(int16(v)))
		return buf, nil

	case TypeInt32:
		v, err := strconv.ParseInt(value, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid int32: %w", err)
		}
		buf := make([]byte, 4)
		bo.PutUint32(buf, uint32(int32(v)))
		return buf, nil

	case TypeInt64:
		v, err := strconv.ParseInt(value, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid int64: %w", err)
		}
		buf := make([]byte, 8)
		bo.PutUint64(buf, uint64(v))
		return buf, nil

	case TypeUint8:
		v, err := strconv.ParseUint(value, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid uint8: %w", err)
		}
		return []byte{byte(v)}, nil

	case TypeUint16:
		v, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid uint16: %w", err)
		}
		buf := make([]byte, 2)
		bo.PutUint16(buf, uint16(v))
		return buf, nil

	case TypeUint32:
		v, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid uint32: %w", err)
		}
		buf := make([]byte, 4)
		bo.PutUint32(buf, uint32(v))
		return buf, nil

	case TypeUint64:
		v, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid uint64: %w", err)
		}
		buf := make([]byte, 8)
		bo.PutUint64(buf, uint64(v))
		return buf, nil

	case TypeFloat32:
		v, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid float32: %w", err)
		}
		buf := make([]byte, 4)
		bo.PutUint32(buf, math.Float32bits(float32(v)))
		return buf, nil

	case TypeFloat64:
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid float64: %w", err)
		}
		buf := make([]byte, 8)
		bo.PutUint64(buf, math.Float64bits(v))
		return buf, nil

	case TypeString:
		if value == "" {
			return nil, fmt.Errorf("empty search string")
		}
		return []byte(value), nil

	case TypeUTF16:
		if value == "" {
			return nil, fmt.Errorf("empty search string")
		}
		runes := []rune(value)
		encoded := utf16.Encode(runes)
		buf := make([]byte, len(encoded)*2)
		for i, u := range encoded {
			bo.PutUint16(buf[i*2:], u)
		}
		return buf, nil

	case TypeBytes:
		return parseHexBytes(value)

	default:
		return nil, fmt.Errorf("unsupported value type")
	}
}

func parseHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty byte pattern")
	}
	parts := strings.Fields(s)
	result := make([]byte, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte %q at position %d: %w", p, i, err)
		}
		result[i] = byte(v)
	}
	return result, nil
}

// compareValues returns -1, 0, or 1 comparing two values of the given type.
// Returns 0 if slices are too short for the value type. (audit M1)
func compareValues(vt ValueType, a, b []byte, bo binary.ByteOrder) int {
	need := valueSize(vt)
	if need > 0 && (len(a) < need || len(b) < need) {
		return 0
	}
	switch vt {
	case TypeInt8:
		va, vb := int8(a[0]), int8(b[0])
		return cmpOrdered(va, vb)
	case TypeInt16:
		return cmpOrdered(int16(bo.Uint16(a)), int16(bo.Uint16(b)))
	case TypeInt32:
		return cmpOrdered(int32(bo.Uint32(a)), int32(bo.Uint32(b)))
	case TypeInt64:
		return cmpOrdered(int64(bo.Uint64(a)), int64(bo.Uint64(b)))
	case TypeUint8:
		return cmpOrdered(a[0], b[0])
	case TypeUint16:
		return cmpOrdered(bo.Uint16(a), bo.Uint16(b))
	case TypeUint32:
		return cmpOrdered(bo.Uint32(a), bo.Uint32(b))
	case TypeUint64:
		return cmpOrdered(bo.Uint64(a), bo.Uint64(b))
	case TypeFloat32:
		return cmpOrdered(math.Float32frombits(bo.Uint32(a)), math.Float32frombits(bo.Uint32(b)))
	case TypeFloat64:
		return cmpOrdered(math.Float64frombits(bo.Uint64(a)), math.Float64frombits(bo.Uint64(b)))
	default:
		// String, UTF16, Bytes — byte-level
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] < b[i] {
				return -1
			} else if a[i] > b[i] {
				return 1
			}
		}
		return cmpOrdered(len(a), len(b))
	}
}

type ordered interface {
	~int8 | ~int16 | ~int32 | ~int64 | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~float32 | ~float64 | ~int
}

func cmpOrdered[T ordered](a, b T) int {
	if a < b {
		return -1
	} else if a > b {
		return 1
	}
	return 0
}

// formatValue converts raw bytes to a human-readable string.
func formatValue(vt ValueType, data []byte, bo binary.ByteOrder) string {
	switch vt {
	case TypeInt8:
		if len(data) < 1 {
			return "?"
		}
		return strconv.FormatInt(int64(int8(data[0])), 10)
	case TypeInt16:
		if len(data) < 2 {
			return "?"
		}
		return strconv.FormatInt(int64(int16(bo.Uint16(data))), 10)
	case TypeInt32:
		if len(data) < 4 {
			return "?"
		}
		return strconv.FormatInt(int64(int32(bo.Uint32(data))), 10)
	case TypeInt64:
		if len(data) < 8 {
			return "?"
		}
		return strconv.FormatInt(int64(bo.Uint64(data)), 10)
	case TypeUint8:
		if len(data) < 1 {
			return "?"
		}
		return strconv.FormatUint(uint64(data[0]), 10)
	case TypeUint16:
		if len(data) < 2 {
			return "?"
		}
		return strconv.FormatUint(uint64(bo.Uint16(data)), 10)
	case TypeUint32:
		if len(data) < 4 {
			return "?"
		}
		return strconv.FormatUint(uint64(bo.Uint32(data)), 10)
	case TypeUint64:
		if len(data) < 8 {
			return "?"
		}
		return strconv.FormatUint(bo.Uint64(data), 10)
	case TypeFloat32:
		if len(data) < 4 {
			return "?"
		}
		return strconv.FormatFloat(float64(math.Float32frombits(bo.Uint32(data))), 'g', -1, 32)
	case TypeFloat64:
		if len(data) < 8 {
			return "?"
		}
		return strconv.FormatFloat(math.Float64frombits(bo.Uint64(data)), 'g', -1, 64)
	case TypeString:
		return string(data)
	case TypeUTF16:
		if len(data) < 2 {
			return "?"
		}
		u16 := make([]uint16, len(data)/2)
		for i := range u16 {
			u16[i] = bo.Uint16(data[i*2:])
		}
		return string(utf16.Decode(u16))
	default:
		return fmtHexBytes(data)
	}
}

func fmtHexBytes(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, " ")
}

func valueTypeName(vt ValueType) string {
	for name, t := range valueTypeNames {
		if t == vt {
			return name
		}
	}
	return "unknown"
}

func getByteOrder(endian string) binary.ByteOrder {
	if strings.ToLower(strings.TrimSpace(endian)) == "big" {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func endianName(bo binary.ByteOrder) string {
	if bo == binary.BigEndian {
		return "big"
	}
	return "little"
}

// structField represents one field in a struct search pattern.
type structField struct {
	Offset    int    `json:"offset"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	valueType ValueType
	encoded   []byte
}

// parseStructPattern parses JSON struct search pattern.
func parseStructPattern(jsonStr string, bo binary.ByteOrder) ([]structField, int, error) {
	var fields []structField
	if err := json.Unmarshal([]byte(jsonStr), &fields); err != nil {
		return nil, 0, fmt.Errorf("invalid struct pattern JSON: %w", err)
	}
	if len(fields) == 0 {
		return nil, 0, fmt.Errorf("empty struct pattern")
	}
	if len(fields) > 32 {
		return nil, 0, fmt.Errorf("too many struct fields (max 32)")
	}

	maxEnd := 0
	for i := range fields {
		f := &fields[i]
		if f.Offset < 0 {
			return nil, 0, fmt.Errorf("field %d: negative offset", i)
		}
		vt, err := parseValueType(f.Type)
		if err != nil {
			return nil, 0, fmt.Errorf("field %d: %w", i, err)
		}
		f.valueType = vt
		enc, err := encodeValue(vt, f.Value, bo)
		if err != nil {
			return nil, 0, fmt.Errorf("field %d: %w", i, err)
		}
		f.encoded = enc
		end := f.Offset + len(enc)
		if end > maxEnd {
			maxEnd = end
		}
	}
	return fields, maxEnd, nil
}

func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
