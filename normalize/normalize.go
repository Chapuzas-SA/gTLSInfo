package normalize

import (
	"encoding/json"
	"fmt"
	"gTLSInfo/common"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var ASNRaw struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

var hostnameRegex = regexp.MustCompile(`^([a-zA-Z0-9\-]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9\-])?\.)+[a-zA-Z\-]{2,}$`)

func normalizeCIDR(cidr string) ([]common.Normalized, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("Not IPv4 address space")
	}
	var addrs []common.Normalized
	current := prefix.Addr()
	for i := 0; i < 1<<(32-prefix.Bits()); i++ {
		addrs = append(addrs,
			common.Normalized{
				Host:       current.String(),
				Port:       443,
				ServerName: "",
			})
		current = current.Next()
	}
	return addrs, nil
}

func normalizeASN(asn string) ([]common.Normalized, error) {
	var (
		prefixes []common.Normalized
		data     []byte
		resp     *http.Response
		err      error
	)

	if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
		return nil, fmt.Errorf("%s", "Invalid ASN")
	}
	if _, err := strconv.ParseUint(asn[2:], 10, 32); err != nil {
		return nil, fmt.Errorf("no se pudo parsear ASN: %w", err)
	}
	if resp, err = http.Get("https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + asn); err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	if data, err = io.ReadAll(resp.Body); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &ASNRaw); err != nil {
		return nil, err
	}
	for _, p := range ASNRaw.Data.Prefixes {
		ips, _ := normalizeCIDR(string(p.Prefix))
		prefixes = append(prefixes, ips...)

	}
	return prefixes, nil
}

func NormalizeLine(line string) ([]common.Normalized, error) {
	if res, err := normalizeASN(line); err == nil {
		return res, nil
	}
	if res, err := normalizeCIDR(line); err == nil {
		return res, nil
	}
	if strings.Contains(line, ":") {
		if host, port, err := net.SplitHostPort(line); err == nil {
			if puint, err := strconv.ParseUint(port, 10, 16); err == nil {
				return []common.Normalized{{Host: host, Port: uint16(puint), ServerName: ""}}, nil
			}
		}
	}
	if ip := net.ParseIP(line); ip != nil {
		return []common.Normalized{{Host: ip.String(), Port: 443, ServerName: ""}}, nil
	}

	if hostnameRegex.MatchString(line) {
		var strs []common.Normalized
		strs = append(strs, common.Normalized{Host: line, Port: 443, ServerName: line})
		return strs, nil
	}

	return nil, fmt.Errorf("Normalization error: %s", line)
}
