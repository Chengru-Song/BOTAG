package vrfs

import (
	"fmt"
  _ "io/ioutil"
  _ "os"
  _ "path/filepath"
  "botag/vrf/p256"
)


func GenerateKey() {
  sk, pk := p256.GenerateKey()
  fmt.Println(sk.Private())
  fmt.Println(pk)

}
