package dmarcreport

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

// MaxXMLBytes caps the decompressed report size. Real aggregate reports are
// well under 1 MB; 5 MB is generous headroom, and the cap exists so a
// hostile gzip/zip bomb cannot balloon a 15 MB message into gigabytes of
// memory.
const MaxXMLBytes = 5 << 20

// FromEmail reads a full RFC 822 report email and returns the decompressed
// aggregate-report XML from its first gzip/zip/xml payload. Reporters differ
// in shape (Google sends a single-part base64 zip body; Yahoo a
// multipart/mixed gzip part), so detection tries, in order: filename
// extension, declared media type, magic bytes.
func FromEmail(r io.Reader) ([]byte, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	h := textproto.MIMEHeader(msg.Header)
	return fromPart(h, msg.Body)
}

// fromPart handles one MIME entity: recurses into multiparts, otherwise
// decodes the transfer encoding and tries to extract a report payload.
func fromPart(h textproto.MIMEHeader, body io.Reader) ([]byte, error) {
	mediaType, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("multipart: %w", err)
			}
			if xmlBytes, err := fromPart(p.Header, p); err == nil {
				return xmlBytes, nil
			}
		}
		return nil, fmt.Errorf("no report payload in multipart message")
	}

	decoded := decodeCTE(h.Get("Content-Transfer-Encoding"), body)
	// Cap the raw payload read: the SMTP server already caps the whole
	// message, but fromPart must stand alone (tests, future callers).
	raw, err := io.ReadAll(io.LimitReader(decoded, MaxXMLBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read part: %w", err)
	}
	if len(raw) > MaxXMLBytes {
		return nil, fmt.Errorf("part exceeds %d bytes", MaxXMLBytes)
	}
	return extractPayload(mediaType, partFilename(h, params), raw)
}

// decodeCTE undoes the Content-Transfer-Encoding. multipart.Part decodes
// quoted-printable itself, but base64 — which every real report attachment
// uses — is left to us, as is the top-level (non-multipart) body.
func decodeCTE(cte string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, newLineStrippingReader(r))
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default: // 7bit, 8bit, binary, empty
		return r
	}
}

// newLineStrippingReader removes CR/LF so wrapped base64 bodies decode.
func newLineStrippingReader(r io.Reader) io.Reader {
	return &lineStripper{r: r}
}

type lineStripper struct{ r io.Reader }

func (l *lineStripper) Read(p []byte) (int, error) {
	buf := make([]byte, len(p))
	for {
		n, err := l.r.Read(buf)
		j := 0
		for _, b := range buf[:n] {
			if b != '\r' && b != '\n' {
				p[j] = b
				j++
			}
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}

func partFilename(h textproto.MIMEHeader, ctParams map[string]string) string {
	if _, params, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil {
		if fn := params["filename"]; fn != "" {
			return fn
		}
	}
	return ctParams["name"]
}

// extractPayload turns one decoded part into report XML, or reports that
// this part isn't a report payload (so multipart walking can move on).
func extractPayload(mediaType, filename string, raw []byte) ([]byte, error) {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".zip") || mediaType == "application/zip" || bytes.HasPrefix(raw, []byte("PK\x03\x04")):
		return unzipReport(raw)
	case strings.HasSuffix(lower, ".gz") || mediaType == "application/gzip" || mediaType == "application/x-gzip" || bytes.HasPrefix(raw, []byte{0x1f, 0x8b}):
		return gunzipReport(raw)
	case strings.HasSuffix(lower, ".xml") || mediaType == "application/xml" || mediaType == "text/xml":
		return raw, nil
	}
	return nil, fmt.Errorf("part %q (%s) is not a report payload", filename, mediaType)
}

func gunzipReport(raw []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	out, err := io.ReadAll(io.LimitReader(gz, MaxXMLBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	if len(out) > MaxXMLBytes {
		return nil, fmt.Errorf("decompressed report exceeds %d bytes", MaxXMLBytes)
	}
	return out, nil
}

func unzipReport(raw []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("unzip: %w", err)
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("unzip %s: %w", f.Name, err)
		}
		defer rc.Close()
		out, err := io.ReadAll(io.LimitReader(rc, MaxXMLBytes+1))
		if err != nil {
			return nil, fmt.Errorf("unzip %s: %w", f.Name, err)
		}
		if len(out) > MaxXMLBytes {
			return nil, fmt.Errorf("decompressed report exceeds %d bytes", MaxXMLBytes)
		}
		return out, nil
	}
	return nil, fmt.Errorf("zip contains no .xml entry")
}
