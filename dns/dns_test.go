package dns

import (
  "testing"
  "math/big"
  "encoding/json"
  "io/ioutil"

  "github.com/GetALittleRough/BOTAG/vrf/p256"
  _ "github.com/GetALittleRough/BOTAG/vrf"
)

func TestReadIdentity(t *testing.T) {
  sk, pk := readIdentity()
  pi, proof := sk.Evaluate([]byte("jason"))
  index, err := pk.ProofToHash([]byte("jason"), proof)
  if err != nil {
    t.Fatal(err)
  } else if pi != index {
    t.Fatal("error while using vrf")
  }
}

func TestHashlen(test *testing.T) {
  test.Log("Test whether hash / Pow(2, hashlen) is different and how it divide")
  sk, _ := readIdentity()
  hash, _ := sk.Evaluate([]byte("jason"))
  t := &big.Int{}
	t.SetBytes(hash[:])

	precision := uint(8 * (len(hash) + 1))
	max, b, err := big.ParseFloat("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0, precision, big.ToNearestEven)
	if b != 16 || err != nil {
		panic("failed to parse big float constant in sortition")
	}

	h := big.Float{}
	h.SetPrec(precision)
	h.SetInt(t)

	ratio := big.Float{}
	cratio, _ := ratio.Quo(&h, max).Float64()

  test.Log("cratio: ", cratio)
}

func TestCrypotographicSortition(t *testing.T) {
  sk, _ := readIdentity()
  slice := []string {
    "jason",
    "jasona",
    "jasonaa",
    "jasonaaa",
  }
  for _, s := range slice {
    t.Log("String: ", s)
    hash, _ := sk.Evaluate([]byte(s))
    cratio := CryptographicSortition(hash, 20, 0.6)
    t.Logf("cratio %s: %v", s, cratio)
  }
}

func TestVerifyFromProof(t *testing.T) {
  t.Log("test VerifyFromProof")
  sk, pk := readIdentity()
  slice := []string {
    "jason",
    "jasona",
    "jasonaa",
    "jasonaaa",
  }
  for _, s := range slice {
    hash, proof := sk.Evaluate([]byte(s))
    sj := CryptographicSortition(hash, 20, 0.6)

    err := VerifyFromProof(hash, []byte(s), proof, pk, 20, 0.6, sj)
    if err != nil {
      t.Fatal(err)
    }
  }
}

func TestReadServer(t *testing.T) {
	s := []Server{
    {
      ID: "json",
      Clients: []Client{
        Client{
          ID:           "ou",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "fu",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "au",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "mu",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "yu",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
      },
      CurrentLevel:   10,
      CurrentTraffic: 34.5,
      Weight:         70.8,
    },
    {
      ID: "json2",
      Clients: []Client{
        Client{
          ID:           "ou",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "fu",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "au",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "mu",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
        Client{
          ID:           "yu",
          Score:        10,
          CurrentProxy: "10.108.87.10",
        },
      },
      CurrentLevel:   10,
      CurrentTraffic: 34.5,
      Weight:         50.8,
    },
  }

  for i, _ := range s {
    s[i].Sk, s[i].Pk = p256.GenerateKey()
  }

  jsonFile, err := json.Marshal(s)
  if err != nil {
    t.Fatal(err)
  }
  saveErr := ioutil.WriteFile("servers.json", jsonFile, 0644)
  if saveErr != nil {
    t.Fatal(saveErr)
  }
}

func TestReadServers(t *testing.T) {
  s, err := ReadServers("servers.json")
  if err != nil {
    t.Fatal(err)
  }
  t.Log(s.SS)
}
