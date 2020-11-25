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

func TestPubkey2Address(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	if err != nil {
		t.Error(err)
	}
	t.Run("generate new acp address", func(t *testing.T) {
		addr, err := Pubkey2Address("0x027ed0f9a0a2b0c3ba4c328c7f5b04a0e4ec670da06dd511e611b5f1d205c432d7", true, false, conf)
		if err != nil {
			t.Error(err)
		}
		expectedAcpAddr := "ckt1qyprj49vann9p94l4qf93xpamwpezh79d0vq4s04k0"
		if addr != expectedAcpAddr {
			t.Fatalf("should return %s, but got %s", expectedAcpAddr, addr)
		}
	})

	t.Run("generate old acp address", func(t *testing.T) {
		addr, err := Pubkey2Address("0x027ed0f9a0a2b0c3ba4c328c7f5b04a0e4ec670da06dd511e611b5f1d205c432d7", true, true, conf)
		if err != nil {
			t.Error(err)
		}
		expectedOldAcpAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykykw254nkwv5ykh75pykyc8hdc8y2lc44asaumhu7"
		if addr != expectedOldAcpAddr {
			t.Fatalf("should return %s, but got %s", expectedOldAcpAddr, addr)
		}
	})
}
