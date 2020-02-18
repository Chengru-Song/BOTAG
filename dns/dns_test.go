package dns

import (
  "testing"
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

func TestVerifiableNumber(t *testing.T) {
  pi, proof := VerifiableNumber([]byte("jason"))
  t.Log(pi, proof)
}
