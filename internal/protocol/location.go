package protocol

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func validAbsoluteCleanPOSIXPath(value string) bool {
	if len(value) < 2 || len(value) > 1024 || value[0] != '/' || value[len(value)-1] == '/' || strings.Contains(value, "//") {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("/._-", rune(character)) {
			continue
		}
		return false
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validProviderOrigin(value string) bool {
	return validSecureURL(value, false)
}

func validGatewayEndpoint(value string) bool {
	return validSecureURL(value, true)
}

func validSecureURL(value string, gateway bool) bool {
	if len(value) == 0 || len(value) > 2048 || !visibleASCII(value) || strings.ContainsAny(value, "%@?#\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.ForceQuery || parsed.Host == "" {
		return false
	}
	if gateway {
		if parsed.Scheme != "https" && parsed.Scheme != "wss" {
			return false
		}
		if !validEndpointPath(parsed.Path) {
			return false
		}
	} else {
		if parsed.Scheme != "https" || parsed.Path != "" {
			return false
		}
	}

	authority, ok := canonicalAuthority(parsed.Host, parsed.Scheme)
	if !ok || authority != parsed.Host {
		return false
	}
	want := parsed.Scheme + "://" + authority
	if gateway {
		want += parsed.Path
	}
	return want == value
}

func canonicalAuthority(authority, scheme string) (string, bool) {
	host := authority
	port := ""
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing < 0 {
			return "", false
		}
		host = authority[1:closing]
		remainder := authority[closing+1:]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") || len(remainder) == 1 {
				return "", false
			}
			port = remainder[1:]
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() || address.Is4In6() || address.String() != host {
			return "", false
		}
		host = "[" + host + "]"
	} else {
		if strings.Count(authority, ":") > 1 {
			return "", false
		}
		if separator := strings.LastIndexByte(authority, ':'); separator >= 0 {
			host = authority[:separator]
			port = authority[separator+1:]
			if host == "" || port == "" {
				return "", false
			}
		}
		address, err := netip.ParseAddr(host)
		switch {
		case err == nil && address.Is4():
			if address.String() != host {
				return "", false
			}
		case err == nil:
			return "", false
		case !validDNSName(host):
			return "", false
		}
	}
	if port != "" {
		if len(port) > 1 && port[0] == '0' {
			return "", false
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || number == 443 || strconv.Itoa(number) != port {
			return "", false
		}
		return host + ":" + port, true
	}
	return host, true
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return !whatwgIPv4Number(labels[len(labels)-1])
}

func whatwgIPv4Number(value string) bool {
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		if len(value) == 2 {
			return false
		}
		for _, character := range []byte(value[2:]) {
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
				return false
			}
		}
		return true
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}

func validEndpointPath(path string) bool {
	if path == "/" {
		return true
	}
	if len(path) < 2 || path[len(path)-1] == '/' || strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range []byte(segment) {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("._~:-", rune(character)) {
				continue
			}
			return false
		}
	}
	return true
}

func visibleASCII(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
