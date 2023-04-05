package reverseguard

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestConfigurationErrors(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	t.Log("Given the need to test constraint on running with an empty \"map\" section.")
	{
		_, err := New(ctx, next, &Config{}, "ReverseGuard")

		testId := 0

		t.Logf("\t Test %d: Whether an error message indicates an empty configuration.", testId)
		require.EqualErrorf(t, err, "empty configuration", "Should be an error message about an empty \"map\" section.")
	}

	t.Log("Given the need to check the constraint on running with missing subnets in one of the configuration sets in the \"map\" section.")
	{
		items := make(map[string]*ReverseProxy, 1)
		items["cloudflare"] = &ReverseProxy{} // empty subnets

		cfg := &Config{Map: items}

		_, err := New(ctx, next, cfg, "ReverseGuard")

		testId := 0

		t.Logf("\tTest %d: Whether a name of configuration in which an error occurred is contained in an error message.", testId)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")

		testId++

		t.Logf("\tTest %d: Whether an error message contain the main idea.", testId)
		require.ErrorContainsf(t, err, "no configured subnets", "An error message should contain the main idea.")
	}

	t.Log("Given the need to check probably errors in header_actions sections")
	{
		testId := 0

		items := make(map[string]*ReverseProxy, 1)
		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{"127.0.0.1/32"},
			HeaderActions: []*HeaderAction{
				{Action: "!!!some random string!!!"},
			},
		}

		cfg := &Config{Map: items}

		_, err := New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether the error in the header_actions section contains information about empty \"source\" field.", testId)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, "action #0", "An error message should contain a number of header action in which an error occurred.")
		require.ErrorContainsf(t, err, "must contain the \"source\" option", "An error message should contain information about the empty \"source\" field.")

		testId++

		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{"127.0.0.1/32"},
			HeaderActions: []*HeaderAction{
				{Action: "", Source: "mock"},
			},
		}
		cfg = &Config{Map: items}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether the error in the header_actions section contains information about empty \"action\" field.", testId)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, "action #0", "An error message should contain a number of header action in which an error occurred.")
		require.ErrorContainsf(t, err, "must contain the \"action\" option", "An error message should contain the \"must contain the \"action\" option\" substring")

		testId++

		invalidAction := "some invalid action"
		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{"127.0.0.1/32"},
			HeaderActions: []*HeaderAction{
				{Action: invalidAction, Source: "mock"},
			},
		}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether the header action contains the \"action\" field with valid value.", testId)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, "action #0", "An error message should contain a number of header action in which an error occurred.")
		require.ErrorContainsf(t, err, fmt.Sprintf("type \"%s\" is not valid", invalidAction), "An error message should contain the \"type \"%s\" is not valid\" substring", invalidAction)

		testId++

		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{"127.0.0.1/32"},
			HeaderActions: []*HeaderAction{
				{Action: ActionCopy, Source: "x-source"},
			},
		}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether an error message will contain information about empty \"target\" field when \"action\" = %s.", testId, ActionCopy)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, "action #0", "An error message should contain a number of header action in which an error occurred.")
		require.ErrorContainsf(t, err, "must contain the \"target\" option", "An error message should contain information about the empty \"target\" field.")

		testId++

		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{"127.0.0.1/32"},
			HeaderActions: []*HeaderAction{
				{Action: ActionRename, Source: "x-source"},
			},
		}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether an error message will contain information about empty \"target\" field when \"action\" = %s.", testId, ActionRename)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, "action #0", "An error message should contain a number of header action in which an error occurred.")
		require.ErrorContainsf(t, err, "must contain the \"target\" option", "An error message should contain information about the empty \"target\" field.")

		testId++

		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{"127.0.0.1/32"},
			HeaderActions: []*HeaderAction{
				{Action: ActionDelete, Source: "x-source"},
			},
		}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether an error will occur if the field \"target\", where \"action\" = %s, is not filled in.", testId, ActionDelete)
		require.NoErrorf(t, err, "If the \"target\" field, where \"action\" = %s, is not filled in, there will be no error.", ActionDelete)
	}

	t.Log("Given the need to check probably errors in static_cidrs sections.")
	{
		invalidSubnet := "127.0.0./33"
		items := make(map[string]*ReverseProxy, 1)
		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{invalidSubnet},
		}
		cfg := &Config{Map: items}

		_, err := New(ctx, next, cfg, "ReverseGuard")

		testId := 0

		t.Logf("\tTest %d: Whether an error in the static_cidrs section contains information about invalid CIDR/subnet.", testId)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, fmt.Sprintf("%q is invalid", invalidSubnet), "An error message should contain information about invalid CIDR/subnet.")

		testId++

		items = make(map[string]*ReverseProxy, 1)
		items["cloudflare"] = &ReverseProxy{
			RawStaticCIDRs: []string{
				"192.168.0.0/16",
				"127.0.0.0/8",
			},
		}
		cfg = &Config{Map: items}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether an error will occur if subnets are specified correctly.", testId)
		require.NoErrorf(t, err, "An error should not occur if the subnets are specified correctly.")
	}

	t.Log("Given the need to check probably errors in dynamic_cidrs sections.")
	{
		testId := 0

		invalidUrl := "!!!some invalid url!!!"
		items := make(map[string]*ReverseProxy, 1)
		items["cloudflare"] = &ReverseProxy{
			DynamicCIDRs: []*DynamicCIDR{
				{Url: invalidUrl},
			},
		}
		cfg := &Config{Map: items}

		_, err := New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether an error will occur if an incorrect URL is specified in the dynamic_cidrs section.", testId)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, fmt.Sprintf("%q is invalid", invalidUrl), "There should be an error if incorrect URL is specified in the dynamic_cidrs section.")

		testId++

		invalidInterval := "!!!invalid interval!!!"
		items["cloudflare"] = &ReverseProxy{
			DynamicCIDRs: []*DynamicCIDR{},
		}

		cfg = &Config{Map: items}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether an error will occur if an incorrect interval is specified in the dynamic_cidrs section.", testId)
		require.ErrorContainsf(t, err, "cloudflare", "An error message should contain a name of configuration in which an error occurred.")
		require.ErrorContainsf(t, err, fmt.Sprintf("invalid interval %q", invalidInterval), "There should be an error if incorrect interval is specified in the dynamic_cidrs section.")

		items["cloudflare"] = &ReverseProxy{
			DynamicCIDRs: []*DynamicCIDR{
				{Url: "https://www.cloudflare.com/ips-v4", RawInterval: "60s"},
				{Url: "https://www.cloudflare.com/ips-v4", RawInterval: "60m"},
				{Url: "https://www.cloudflare.com/ips-v4", RawInterval: "60h"},
				{Url: "https://www.cloudflare.com/ips-v4", RawInterval: "60d"},
				{Url: "https://www.cloudflare.com/ips-v4", RawInterval: "60w"},
				// &DynamicCIDR{Url: "file:///var/log/dynip.txt", RawInterval: "60w"}, TODO : Add tests for local file url
			},
		}

		cfg = &Config{Map: items}

		_, err = New(ctx, next, cfg, "ReverseGuard")

		t.Logf("\tTest %d: Whether an error will occur if all entries in the dynamic_cidrs section are specified correctly.", testId)
		require.NoErrorf(t, err, "An error should not occur if all entries in the dynamic_cidrs section are specified correctly.")

	}
}
