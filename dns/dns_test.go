package dns

import (
  "testing"
  "math/big"
  "encoding/json"
  "io/ioutil"
  "os"

  "github.com/GetALittleRough/BOTAG/vrf/p256"
  _ "github.com/GetALittleRough/BOTAG/vrf"
)

func TestSaveIdentity(t *testing.T) {
  sk, _ := p256.GenerateKey()
  t.Logf("%s\n", sk.ToByte())
}

func TestReadIdentity(t *testing.T) {
  var key p256.PrivateKey
  file, fileErr := os.Open("testkeys.json")
  if fileErr != nil {
    t.Fatal(fileErr)
  }
  defer file.Close()
  jsonString, marshalErr := ioutil.ReadAll(file)
  if marshalErr != nil {
    t.Fatal(marshalErr)
  }
  unmarshalErr := json.Unmarshal(jsonString, &key)
  t.Log(key)
  if unmarshalErr != nil {
    t.Fatal(unmarshalErr)
  }

}

func TestHashlen(test *testing.T) {
  test.Log("Test whether hash / Pow(2, hashlen) is different and how it divide")
  sk, _ := readIdentity("keys.json")
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
  sk, _ := readIdentity("keys.json")
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
  sk, pk := readIdentity("keys.json")
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
      Weight:         69.8,
    },
  }

  for i, _ := range s {
    sk, pk := p256.GenerateKey()
    s[i].Sk = sk.ToByte()
    s[i].Pk = pk.ToByte()
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
  var sk p256.PrivateKey
  for _, s := range s.SS {
    err := json.Unmarshal(s.Sk, &sk)
    if err != nil {
      t.Fatal(err)
    }
    t.Log(sk.Public())
  }
}

func TestDNSResolve(t *testing.T) {
  ss, err := ReadServers("servers.json")
  if err != nil {
    t.Fatal("Cannot read servers")
  }
  proofs := make([][]byte, 0)
  randoms := make([]int, 0)
  ms := make([][32]byte, 0)

  seed := []byte("jason")
  for _, s := range ss.SS {
    var sk p256.PrivateKey
    json.Unmarshal(s.Sk, &sk)
    hash, proof := sk.Evaluate(seed)
    N := ss.SumWeight()
    P := float64(s.Weight) / N
    sj := CryptographicSortition(hash, N, P)
    t.Logf("sj: %d", sj)
    proofs = append(proofs, proof)
    ms = append(ms, hash)
    randoms = append(randoms, sj)
  }

  index, resolveErr := DNSResolve(ss, proofs, randoms, seed, ms)
  if resolveErr != nil {
    t.Fatal(resolveErr)
  }
  t.Log(ss.SS[index].ID)
}
