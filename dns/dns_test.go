package dns

import (
	"testing"
)

func TestInit(t *testing.T) {
	t.Log("ReadConfig test")
	err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCurrentScore(t *testing.T) {
	t.Log("Testing result")
	t.Log(currentScore(3.1, 3.4, 5.2))
}
