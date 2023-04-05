package reverseguard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	Second = "s"
	Minute = "m"
	Hour   = "h"
	Day    = "d"
	Week   = "w"

	ActionRename = "rename"
	ActionDelete = "delete"
	ActionCopy   = "copy"
)

type HeaderAction struct {
	Action string `mapstructure:"action"`
	Source string `mapstructure:"source"`
	Target string `mapstructure:"target,omitempty"`
}

type ForbiddenResponse struct {
	code    int    `mapstructure:"code,omitempty"`
	content string `mapstructure:"content,omitempty"`
}

type Config struct {
	Custom403Response *ForbiddenResponse       `mapstructure:"rewrite_403,omitempty"`
	Map               map[string]*ReverseProxy `mapstructure:"map,omitempty"`
}

type Interval struct {
	Number int
	Unit   string
}

type ReverseProxy struct {
	HeaderActions  []*HeaderAction `mapstructure:"header_actions,omitempty"`
	RawStaticCIDRs []string        `mapstructure:"static_cidrs,omitempty"`
	staticCIDRS    []*net.IPNet
	DynamicCIDRs   []*DynamicCIDR `mapstructure:"dynamic_cidrs,omitempty"`
}

func (r *ReverseProxy) applyHeaderOptions(req *http.Request) {
	for _, act := range r.HeaderActions {
		switch act.Action {
		case ActionCopy:
			if hVal := req.Header.Get(act.Source); hVal != "" {
				req.Header.Del(act.Target)
				req.Header.Add(act.Target, hVal)
			}
		case ActionRename:
			if hVal := req.Header.Get(act.Source); hVal != "" {
				req.Header.Del(act.Source)
				req.Header.Del(act.Target)
				req.Header.Add(act.Target, hVal)
			}
		case ActionDelete:
			req.Header.Del(act.Source)
		}
	}
}

func (r *ReverseProxy) contains(ip net.IP) bool {
	for _, trustedCIDR := range r.staticCIDRS {
		if trustedCIDR.Contains(ip) {
			return true
		}
	}

	for _, trustedCIDRList := range r.DynamicCIDRs {
		for _, trustedCIDR := range trustedCIDRList.cidrList {
			if trustedCIDR.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func (r *ReverseProxy) countCIDRs() int {
	num := len(r.staticCIDRS)

	for _, v := range r.DynamicCIDRs {
		num += len(v.cidrList)
	}

	return num
}

func NewInterval(number int, unit string) (*Interval, error) {
	if number <= 0 {
		return nil, fmt.Errorf("the interval \"%v%q\" is invalid because the number must be greater than zero", number, unit)
	}

	if unit != Second && unit != Minute && unit != Hour && unit != Day && unit != Week {
		return nil, fmt.Errorf("the interval \"%v%q\" is invalid because the unit is unknown. Available units: s, m, h, d, w", number, unit)
	}

	return &Interval{
		Number: number,
		Unit:   unit,
	}, nil
}

type DynamicCIDR struct {
	Url         string `mapstructure:"url"`
	interval    *Interval
	RawInterval string `mapstructure:"interval,omitempty"`
	cidrList    []*net.IPNet
}

func (d *DynamicCIDR) isFileUrl() bool {
	return strings.HasPrefix(d.Url, "file://")
}

func (d *DynamicCIDR) isHttpUrl() bool {
	return strings.HasPrefix(d.Url, "http://") || strings.HasPrefix(d.Url, "https://")
}

func (d *DynamicCIDR) hasCIDR(cidr string) bool {
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}

	for _, v := range d.cidrList {
		item := v.String()

		if !strings.Contains(item, "/") {
			item += "/32"
		}

		if cidr == item {
			return true
		}
	}

	return false
}

func (d *DynamicCIDR) update() (int, int, error) {
	var added int = 0
	var skipped int = 0

	if d.isFileUrl() {
		filePath := d.Url[7:len(d.Url)]

		_, err := os.Stat(filePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return 0, 0, fmt.Errorf("the file %q does not exist", filePath)
			}
			if errors.Is(err, os.ErrPermission) {
				return 0, 0, fmt.Errorf("no permissions to read the file %q", filePath)
			}
		}

		// open the file
		file, err := os.Open(filePath)
		if err != nil {
			return 0, 0, err
		}

		defer file.Close()

		fileScanner := bufio.NewScanner(file)

		var CIDRList []*net.IPNet

		for fileScanner.Scan() {
			entry := fileScanner.Text()

			if !strings.Contains(entry, "/") {
				entry += "/32"
			}

			if d.hasCIDR(entry) {
				skipped++
				continue
			}

			_, cidr, err := net.ParseCIDR(entry)
			if err != nil {
				return 0, 0, err
			}

			added++
			CIDRList = append(d.cidrList, cidr)
		}

		d.cidrList = CIDRList // not replace
	} else if d.isHttpUrl() {
		resp, err := http.Get(d.Url)
		if err != nil {
			return 0, 0, err
		}

		if resp.StatusCode != 304 && resp.StatusCode != 200 {
			return 0, 0, fmt.Errorf("response code %d is not acceptable", resp.StatusCode)
		}

		r := http.MaxBytesReader(nil, resp.Body, 2000)
		buff, err := io.ReadAll(r)
		if err != nil {
			return 0, 0, err
		}

		defer resp.Body.Close()

		replacer := strings.NewReplacer("\r\n", "\n", "\r", "\n", "\v", "\n", "\f", "\n")
		content := replacer.Replace(string(buff))

		var CIDRList []*net.IPNet

		for _, v := range strings.Split(content, "\n") {
			v = strings.TrimSpace(v)

			if v == "" {
				continue
			}

			if !strings.Contains(v, "/") {
				v += "/32"
			}

			if d.hasCIDR(v) {
				skipped++
				continue
			}

			_, cidr, err := net.ParseCIDR(v)
			if err != nil {
				d.cidrList = nil
				return 0, 0, errors.New("invalid URL content")
			}

			added++
			CIDRList = append(CIDRList, cidr)
		}

		d.cidrList = CIDRList // hot replace
	} else {
		panic("not implemented")
	}

	return added, skipped, nil
}
