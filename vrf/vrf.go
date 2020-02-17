package vrf

import (
	"fmt"
	_ "github.com/google/keytransparency/core/crypto/vrf"
  "github.com/google/keytransparency/core/crypto/vrf/p256"
  _ "io/ioutil"
  _ "os"
  _ "path/filepath"
  "../dns"
)

func main() {
  GenerateKey()
}

func GenerateKey() {
  sk, pk := p256.GenerateKey()
  fmt.Println(&sk)
  fmt.Println("pk: ", pk)

	s := dns.Server{
		ID: "json",
		Clients: []dns.Client{

			dns.Client{
				ID:           "ou",
				Score:        10,
				CurrentProxy: "10.108.87.10",
			},
			dns.Client{
				ID:           "fu",
				Score:        10,
				CurrentProxy: "10.108.87.10",
			},
			dns.Client{
				ID:           "au",
				Score:        10,
				CurrentProxy: "10.108.87.10",
			},
			dns.Client{
				ID:           "mu",
				Score:        10,
				CurrentProxy: "10.108.87.10",
			},
			dns.Client{
				ID:           "yu",
				Score:        10,
				CurrentProxy: "10.108.87.10",
			},
		},
		CurrentLevel:   10,
		CurrentTraffic: 34.5,
		Weight:         70.8,
	}
  s.quickSort()
}
