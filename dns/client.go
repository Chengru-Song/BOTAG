package dns

import (
	_ "fmt"
)

type Client struct {
	ID           string
	Score        int
	CurrentProxy string
}
