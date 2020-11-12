package client

import (
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	"testing"
)

func TestIsOldAcpAddress(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	if err != nil {
		t.Error(err)
	}
	cases := []struct {
		Name     string
		Addr     string
		Conf     *config.Config
		Expected bool
	}{
		{"old acp address", "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu", conf, true},
		{"new acp address", "ckt1qg8mxsu48mncexvxkzgaa7mz2g25uza4zpz062relhjmyuc52ps3razydxllj3dzvalznz08fs6dugc5mwkhxqlfuww", conf, false},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if ans, _ := IsOldAcpAddress(c.Addr, c.Conf); ans != c.Expected {
				t.Fatalf("should return %t, but got %t", c.Expected, ans)
			}
		})
	}
}
