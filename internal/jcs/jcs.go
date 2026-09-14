// Package jcs implements RFC 8785 JSON canonicalization for the locked
// Provider Contract documents.
package jcs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxDepth = 64

var (
	ErrInvalidJSON       = errors.New("JCS input is not one strict JSON document")
	ErrUnsupportedNumber = errors.New("JCS input number is outside the supported Contract integer domain")
)

// Canonicalize returns RFC 8785 canonical JSON. Duplicate object members and
// invalid Unicode fail closed.
func Canonicalize(document []byte) ([]byte, error) {
	if len(document) == 0 || !utf8.Valid(document) || !validUnicodeEscapes(document) {
		return nil, ErrInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	value, err := parseValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidJSON
	}
	var output bytes.Buffer
	if err := appendCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func Marshal(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return Canonicalize(document)
}

// DigestExcluding computes the Provider Contract's top-level exclusion digest.
// Exactly one named member must exist and is removed before canonicalization.
func DigestExcluding(value any, excluded string) (string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidJSON
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil {
		return "", ErrInvalidJSON
	}
	if _, ok := object[excluded]; !ok {
		return "", ErrInvalidJSON
	}
	delete(object, excluded)
	canonical, err := Marshal(object)
	if err != nil {
		return "", err
	}
	return DigestBytes(canonical), nil
}

func Digest(value any) (string, error) {
	canonical, err := Marshal(value)
	if err != nil {
		return "", err
	}
	return DigestBytes(canonical), nil
}

func DigestBytes(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parseValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrInvalidJSON
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalidJSON
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return nil, ErrInvalidJSON
			}
			name, ok := nameToken.(string)
			if !ok {
				return nil, ErrInvalidJSON
			}
			if _, duplicate := object[name]; duplicate {
				return nil, ErrInvalidJSON
			}
			value, err := parseValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, ErrInvalidJSON
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			value, err := parseValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, ErrInvalidJSON
		}
		return array, nil
	default:
		return nil, ErrInvalidJSON
	}
}

func appendCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		appendJSONString(output, typed)
	case json.Number:
		number, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
			return ErrUnsupportedNumber
		}
		appendNumber(output, number)
	case []any:
		output.WriteByte('[')
		for index, element := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendCanonical(output, element); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool { return lessUTF16(keys[left], keys[right]) })
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			appendJSONString(output, key)
			output.WriteByte(':')
			if err := appendCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return ErrInvalidJSON
	}
	return nil
}

func appendNumber(output *bytes.Buffer, number float64) {
	if number == 0 {
		output.WriteByte('0')
		return
	}
	format := byte('f')
	absolute := math.Abs(number)
	if absolute < 1e-6 || absolute >= 1e21 {
		format = 'e'
	}
	encoded := strconv.FormatFloat(number, format, -1, 64)
	if format == 'e' {
		if exponent := strings.LastIndexByte(encoded, 'e'); exponent >= 0 && exponent+3 < len(encoded) && encoded[exponent+2] == '0' {
			encoded = encoded[:exponent+2] + encoded[exponent+3:]
		}
	}
	output.WriteString(encoded)
}

func lessUTF16(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}

func appendJSONString(output *bytes.Buffer, value string) {
	const hex = "0123456789abcdef"
	output.WriteByte('"')
	for _, character := range []byte(value) {
		switch character {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteByte(character)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if character < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hex[character>>4])
				output.WriteByte(hex[character&0x0f])
			} else {
				output.WriteByte(character)
			}
		}
	}
	output.WriteByte('"')
}

func validUnicodeEscapes(document []byte) bool {
	inString := false
	for index := 0; index < len(document); index++ {
		switch document[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			index++
			if index >= len(document) {
				return false
			}
			if document[index] != 'u' {
				continue
			}
			if index+4 >= len(document) {
				return false
			}
			value, ok := fourHex(document[index+1 : index+5])
			if !ok {
				return false
			}
			index += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if index+6 >= len(document) || document[index+1] != '\\' || document[index+2] != 'u' {
				return false
			}
			low, ok := fourHex(document[index+3 : index+7])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		}
	}
	return !inString
}

func fourHex(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result uint16
	for _, character := range value {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}
