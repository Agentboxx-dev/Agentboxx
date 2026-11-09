// agentbox-verify: independent verifier for Agentboxx logs (docs/log-format.md).
//
// Standard library only. Usage:
//
//	agentbox-verify <log.ndjson> [--receipt receipt.json --pubkey KEY] [--key-file PATH]
//
// Exit codes: 0 intact, 1 tampered or corrupt, 2 incomplete, 3 bad input.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
	"math/big"
)

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"



var smallOrderY = func() []*big.Int {
	hexes := []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // y = 0
		"0100000000000000000000000000000000000000000000000000000000000000", // y = 1
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p-1
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	}
	out := make([]*big.Int, len(hexes))
	for i, h := range hexes {
		b, _ := hex.DecodeString(h)
		out[i] = leToInt(b)
	}
	return out
}()

var fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

func leToInt(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	rev[0] &= 0x7f // clear the sign bit (top bit of the last LE byte)
	return new(big.Int).SetBytes(rev)
}

func isSmallOrder(pub []byte) bool {
	y := leToInt(pub)
	y.Mod(y, fieldP)
	for _, s := range smallOrderY {
		if y.Cmp(s) == 0 {
			return true
		}
	}
	return false
}

// ---------- canonical JSON (matches Python json.dumps(sort_keys, separators, ensure_ascii=False)) ----------

func canon(v interface{}) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanon(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanon(b *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		// Keep the original number text: the log was written by Python, whose float
		// formatting Go cannot reproduce byte-for-byte in every case.
		b.WriteString(t.String())
	case string:
		writeString(b, t)
	case []interface{}:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // UTF-8 byte order == code point order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanon(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", v)
	}
	return nil
}

// Python escapes only ", \, and control characters below 0x20 when ensure_ascii=False.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				var buf [utf8.UTFMax]byte
				n := utf8.EncodeRune(buf[:], r)
				b.Write(buf[:n])
			}
		}
	}
	b.WriteByte('"')
}

func parseJSON(data []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacHex(key []byte, msg []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

// ---------- verification ----------

type state struct {
	count    int64
	lastHash string
	lastType string
}

func verifyLog(data []byte, hmacKey []byte) (problems []string, st state) {
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil, st
	}
	prev := genesis
	var expected int64 = 1
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		line = strings.TrimSuffix(line, "\r")
		v, err := parseJSON([]byte(line))
		rec, ok := v.(map[string]interface{})
		if err != nil || !ok {
			problems = append(problems, fmt.Sprintf("line %d: unreadable record", n))
			continue
		}
		ev, ok1 := rec["event"].(map[string]interface{})
		seqNum, ok2 := ev["seq"].(json.Number)
		prevHash, ok3 := rec["prev_hash"].(string)
		hash, ok4 := rec["hash"].(string)
		etype, _ := ev["event_type"].(string)
		seq, serr := seqNum.Int64()
		if !ok1 || !ok2 || !ok3 || !ok4 || serr != nil {
			problems = append(problems, fmt.Sprintf("line %d: unreadable record", n))
			continue
		}
		if seq != expected {
			problems = append(problems, fmt.Sprintf("line %d: sequence gap (expected %d, got %d)", n, expected, seq))
		}
		expected = seq + 1
		if prevHash != prev {
			problems = append(problems, fmt.Sprintf("line %d: chain broken", n))
		}
		body, err := canon(ev)
		if err != nil {
			problems = append(problems, fmt.Sprintf("line %d: unreadable record", n))
			continue
		}
		// hash = sha256_hex(prev_hash + sha256_hex(canon(event))); uses the recorded prev_hash
		// so that a single edit is reported once, as "content was modified".
		if sha256Hex([]byte(prevHash+sha256Hex(body))) != hash {
			problems = append(problems, fmt.Sprintf("line %d: content was modified", n))
		}
		if hmacKey != nil {
			sig, _ := rec["sig"].(string)
			if !hmac.Equal([]byte(hmacHex(hmacKey, []byte(hash))), []byte(sig)) {
				problems = append(problems, fmt.Sprintf("line %d: bad signature", n))
			}
		}
		prev = hash
		st = state{count: seq, lastHash: hash, lastType: etype}
	}
	return problems, st
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// loadPubKey accepts 64 hex chars, or a path to a file holding hex text or 32 raw bytes.
func loadPubKey(arg string) (ed25519.PublicKey, error) {
	if isHex(arg, 64) {
		b, _ := hex.DecodeString(arg)
		return ed25519.PublicKey(b), nil
	}
	raw, err := os.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	if s := strings.TrimSpace(string(raw)); isHex(s, 64) {
		b, _ := hex.DecodeString(s)
		return ed25519.PublicKey(b), nil
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("public key must be 32 bytes (64 hex characters, or a file containing either)")
}

func loadHMACKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}

// verifyReceipt checks the Ed25519 signature over canon(payload) and that the payload
// matches the verified log. A manifest-style payload ("records") is accepted as well.
func verifyReceipt(path string, pub ed25519.PublicKey, st state) (problems []string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := parseJSON(raw)
	r, ok := v.(map[string]interface{})
	if err != nil || !ok {
		return nil, fmt.Errorf("receipt is not a JSON object")
	}
	payload, ok := r["payload"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("receipt has no payload object")
	}
	sigHex, _ := r["sig"].(string)
	if sigHex == "" {
		sigHex, _ = r["signature"].(string)
	}
	sig, derr := hex.DecodeString(sigHex)
	if derr != nil || len(sig) != ed25519.SignatureSize {
		return []string{"receipt signature is malformed"}, nil
	}
	msg, err := canon(payload)
	if err != nil {
		return nil, err
	}
	if isSmallOrder(pub) {
		problems = append(problems, "public key is a low-order point and is rejected")
		return problems, nil
	}
	if !ed25519.Verify(pub, msg, sig) {
		return []string{"receipt signature is invalid (forged or wrong key)"}, nil
	}
	cnt, ok := payload["record_count"].(json.Number)
	if !ok {
		cnt, ok = payload["records"].(json.Number)
	}
	if c, cerr := cnt.Int64(); !ok || cerr != nil || c != st.count {
		problems = append(problems, fmt.Sprintf("receipt record_count %v does not match log (%d records)", cnt, st.count))
	}
	if fh, _ := payload["final_hash"].(string); fh != st.lastHash {
		problems = append(problems, "receipt final_hash does not match the log's last hash: truncated or modified")
	}
	return problems, nil
}

// verifyManifest checks the HMAC-signed closing manifest (format 0.1), if present and a key is given.
func verifyManifest(logPath string, key []byte, st state) (found bool, problems []string) {
	mp := strings.TrimSuffix(logPath, filepath.Ext(logPath)) + ".manifest.json"
	raw, err := os.ReadFile(mp)
	if err != nil {
		return false, nil
	}
	if key == nil {
		return true, nil
	}
	v, err := parseJSON(raw)
	m, _ := v.(map[string]interface{})
	payload, _ := m["payload"].(map[string]interface{})
	sig, _ := m["sig"].(string)
	if err != nil || payload == nil {
		return true, []string{"manifest is unreadable"}
	}
	body, _ := canon(payload)
	if !hmac.Equal([]byte(hmacHex(key, body)), []byte(sig)) {
		return true, []string{"manifest signature is invalid"}
	}
	rec, _ := payload["records"].(json.Number)
	c, cerr := rec.Int64()
	fh, _ := payload["final_hash"].(string)
	if cerr != nil || c != st.count || fh != st.lastHash {
		return true, []string{"log does not match its signed manifest: truncated or modified"}
	}
	return true, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agentbox-verify <log.ndjson> [--receipt receipt.json --pubkey KEY|FILE] [--key-file PATH]")
}

func fail3(format string, a ...interface{}) int {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	return 3
}

func run(args []string) int {
	var logPath, receiptPath, pubArg, keyFile string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasEq := strings.Cut(a, "=")
		switch name {
		case "--receipt", "--pubkey", "--key-file":
			if !hasEq {
				if i+1 >= len(args) {
					usage()
					return fail3("%s needs a value", name)
				}
				i++
				val = args[i]
			}
			switch name {
			case "--receipt":
				receiptPath = val
			case "--pubkey":
				pubArg = val
			default:
				keyFile = val
			}
		case "-h", "--help":
			usage()
			return 0
		default:
			if strings.HasPrefix(a, "--") || logPath != "" {
				usage()
				return fail3("unexpected argument %q", a)
			}
			logPath = a
		}
	}
	if logPath == "" {
		usage()
		return 3
	}
	if (receiptPath == "") != (pubArg == "") {
		return fail3("--receipt and --pubkey must be given together")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		return fail3("%v", err)
	}
	var pub ed25519.PublicKey
	if pubArg != "" {
		if pub, err = loadPubKey(pubArg); err != nil {
			return fail3("public key: %v", err)
		}
	}
	var hmacKey []byte
	if keyFile != "" {
		if hmacKey, err = loadHMACKey(keyFile); err != nil {
			return fail3("key file: %v", err)
		}
	}

	problems, st := verifyLog(data, hmacKey)
	closed := st.lastType == "session.end"

	if receiptPath != "" {
		rp, rerr := verifyReceipt(receiptPath, pub, st)
		if rerr != nil {
			return fail3("receipt: %v", rerr)
		}
		problems = append(problems, rp...)
		if len(rp) == 0 {
			closed = true
		}
	}
	if found, mp := verifyManifest(logPath, hmacKey, st); found {
		problems = append(problems, mp...)
		if len(mp) == 0 && hmacKey != nil {
			closed = true
		}
	}

	if len(problems) > 0 {
		fmt.Println("TAMPERED OR CORRUPT:")
		for _, p := range problems {
			fmt.Println("  - " + p)
		}
		return 1
	}
	if !closed {
		fmt.Println("INCOMPLETE:")
		fmt.Println("  - no session.end record and no verified receipt or manifest: the session crashed, is still running, or the end of the log was removed")
		return 2
	}
	fmt.Printf("OK: hash chain valid (%d records)", st.count)
	if receiptPath != "" {
		fmt.Print(", receipt signature valid")
	}
	if hmacKey != nil {
		fmt.Print(", HMAC signatures valid")
	}
	fmt.Println()
	return 0
}

func main() {
	os.Exit(run(os.Args[1:]))
}