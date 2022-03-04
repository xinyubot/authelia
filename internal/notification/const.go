package notification

import "regexp"

const (
	fileNotifierMode = 0600
)

const (
	rfc5322DateTimeLayout = "Mon, 2 Jan 2006 15:04:05 -0700"
)

const (
	crlf              = "\r\n"
	doubleCRLF        = crlf + crlf
	rfc2822MIMEHeader = "MIME-Version: 1.0" + doubleCRLF + "This is a message in Mime Format. If you see this, your mail reader does not support this format." + doubleCRLF
)

const (
	rfc4880HashSymbolSHA1   = "pgp-sha1"
	rfc4880HashSymbolSHA256 = "pgp-sha256"
	rfc4880HashSymbolSHA384 = "pgp-sha384"
	rfc4880HashSymbolSHA512 = "pgp-sha512"
)

var (
	reEOLWhitespace      = regexp.MustCompile(`[ \t]+(\r\n|\n|\r|\f)`)
	reNonRFC2822Newlines = regexp.MustCompile(`([^\r])\n`)
)
