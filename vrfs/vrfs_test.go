package vrfs

import (
	"testing"
	"fmt"
  _ "github.com/google/keytransparency/core/crypto/vrf"
  "github.com/google/keytransparency/core/crypto/vrf/p256"
  "io/ioutil"
  "os"
  "path/filepath"
)

func testGenerateKey(t *testing.T) {
	t.Log("testing GenerateKey")
	// read the absolute path of keystore file
	path, configErr := filepath.Abs("./")
	if configErr != nil {
		fmt.Println("read configuration file failed")
		fmt.Println(configErr)
	}
	PubkeyPath := filepath.Join(path, "./test_files/pub_pk.pem")
  PrivkeyPath := filepath.Join(path, "./test_files/priv_sk")

	Pubkey, _ := os.Open(PubkeyPath)
	Privkey, _ := os.Open(PrivkeyPath)
	defer Pubkey.Close()
  defer Privkey.Close()
  PubkeyByte, _ := ioutil.ReadAll(Pubkey)
  PrivkeyByte, _ := ioutil.ReadAll(Privkey)
  fmt.Printf("Public Key: %s\nPrivate Key:%s\n", PubkeyByte, PrivkeyByte)
  

  // read from raw files
  // sk, pk := p256.GenerateKey()

  sk, err := p256.NewVRFSignerFromPEM([]byte(PrivkeyByte))
  if err != nil {
    t.Fatal(err)
  }
  fmt.Println(sk)
}

func TestGenerateKey2(t *testing.T) {
  GenerateKey()
}
