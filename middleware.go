package reverseguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type ReverseGuard struct {
	next   http.Handler
	name   string
	config *Config
}

func (r *ReverseGuard) lookupTrustedIp(ip net.IP) *ReverseProxy {
	for _, proxy := range r.config.Map {
		if proxy.contains(ip) {
			return proxy
		}
	}

	return nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	plugin := &ReverseGuard{
		next:   next,
		name:   name,
		config: config,
	}

	if len(config.Map) == 0 {
		return nil, errors.New("empty configuration")
	} else {
		for name, proxy := range config.Map {
			if len(proxy.DynamicCIDRs) == 0 && len(proxy.RawStaticCIDRs) == 0 {
				return nil, fmt.Errorf("error in %q reverse proxy configuration: no configured subnets (CIDRs). This middleware will not be used", name)
			}

			for i, act := range proxy.HeaderActions {
				if act.Source == "" {
					return nil, fmt.Errorf("error in %q reverse proxy configuration: action #%d must contain the \"source\" option", name, i)
				}

				switch act.Action {
				case ActionCopy, ActionRename:
					if act.Target == "" {
						return nil, fmt.Errorf("error in %q reverse proxy configuration: action #%d must contain the \"target\" option", name, i)
					}
				case ActionDelete:
					// nop
				case "":
					return nil, fmt.Errorf("error in %q reverse proxy configuration: action #%d must contain the \"action\" option", name, i)
				default:
					return nil, fmt.Errorf("error in %q reverse proxy configuration: action #%d of the type \"%s\" is not valid", name, i, act.Action)
				}

			}

			for _, v := range proxy.RawStaticCIDRs {
				if !strings.Contains(v, "/") {
					v += "/32"
				}

				_, cidr, err := net.ParseCIDR(v)
				if err != nil {
					return nil, fmt.Errorf("error in %q reverse proxy configuration: the static CIDR %q is invalid", name, v)
				}

				proxy.staticCIDRS = append(proxy.staticCIDRS, cidr)
			}

			proxy.RawStaticCIDRs = nil
			intervalRegex := regexp.MustCompile(`^(\d+)(s|h|d|w|m|M)$`)

			for _, dynamicCIDR := range proxy.DynamicCIDRs {
				_, err := url.ParseRequestURI(dynamicCIDR.Url)
				if err != nil {
					return nil, fmt.Errorf("error in %q reverse proxy configuration: the url %q is invalid", name, dynamicCIDR.Url)
				}

				if dynamicCIDR.RawInterval != "" {
					matches := intervalRegex.FindAllStringSubmatch(dynamicCIDR.RawInterval, -1)
					invalidIntervalError := fmt.Errorf("error in %q reverse proxy configuration, endpoint %q: invalid interval %q", name, dynamicCIDR.Url, dynamicCIDR.RawInterval)

					if len(matches) == 0 {
						return nil, invalidIntervalError
					}

					number, err := strconv.Atoi(matches[0][1])
					if err != nil {
						return nil, invalidIntervalError
					}

					interval, err := NewInterval(number, matches[0][2])
					if err != nil {
						return nil, fmt.Errorf("error in %q reverse proxy configuration, endpoint %q: %s", name, dynamicCIDR.Url, err.Error())
					}

					dynamicCIDR.interval = interval
					dynamicCIDR.RawInterval = ""
				}

				added, _, err := dynamicCIDR.update()
				if err != nil {
					return nil, fmt.Errorf("error in %q reverse proxy configuration, endpoint %q: %s", name, dynamicCIDR.Url, err.Error())
				}

				writeOut(fmt.Sprintf("Reverse proxy %q, endpoint %q has been updated. New number of subnets: %d", name, dynamicCIDR.Url, added))
				writeOut(fmt.Sprintf("Reverse proxy %q, total number of subnets: %d", name, proxy.countCIDRs()))

				if dynamicCIDR.interval != nil {
					go func(dyn *DynamicCIDR, proxy *ReverseProxy) {
						var timeUnit int

						switch dyn.interval.Unit {
						case "s":
							timeUnit = int(time.Second)
						case "m":
							timeUnit = int(time.Minute)
						case "h":
							timeUnit = int(time.Hour)
						case "d":
							timeUnit = int(time.Hour * 24)
						case "w":
							timeUnit = int(time.Hour * 24 * 7)
						}

						interval := time.Duration(dyn.interval.Number * timeUnit)

						writeOut(fmt.Sprintf(
							"Reverse proxy %q, CIDR list syncing from endpoint %q is started. Interval %d%s. Next run at %s.",
							name,
							dyn.Url,
							dyn.interval.Number,
							dyn.interval.Unit,
							time.Now().Add(interval).Format(time.RFC822),
						))

						for {
							time.Sleep(interval)

							added, _, err := dyn.update()
							nextRun := time.Now().Add(interval).Format(time.RFC822)

							if err != nil {
								writeErr(fmt.Sprintf(
									"Reverse proxy %q, failed to update subnet list at endpoint %q: %s. Next run at %s",
									name,
									dyn.Url,
									err.Error(),
									nextRun,
								))
							}

							writeOut(fmt.Sprintf(
								"Reverse proxy %q, endpoint %q has been succefully updated. New number of subnets: %d. Next run at %s",
								name,
								dyn.Url,
								added,
								nextRun,
							))
							writeOut(fmt.Sprintf("Reverse proxy %q, total number of subnets: %d", name, proxy.countCIDRs()))
						}
					}(dynamicCIDR, proxy)
				}
			}

			writeOut(fmt.Sprintf("The reverse proxy %q is ready to go. Total number of IP subnets: %d.", name, proxy.countCIDRs()))
		}
	}

	return plugin, nil
}

func (r *ReverseGuard) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ipParts := strings.SplitN(req.RemoteAddr, ":", 2)

	reverse := r.lookupTrustedIp(net.ParseIP(ipParts[0]))

	if reverse == nil {
		if r.config.Custom403Response.code != 0 {
			http.Error(rw, r.config.Custom403Response.content, r.config.Custom403Response.code)
		} else {
			http.Error(rw, "", http.StatusForbidden)
		}

		return
	}

	reverse.applyHeaderOptions(req)
	r.next.ServeHTTP(rw, req)
}
