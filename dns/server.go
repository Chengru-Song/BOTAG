package dns

import (
	_ "fmt"
  "github.com/GetALittleRough/BOTAG/vrf/p256"
)

// Must generate key after initialized this struct
type Server struct {
	ID             string
	Clients        []Client
	AvgScore       float32
	CurrentLevel   int
	CurrentTraffic float32
	Weight         float32
  Pk             []byte  `json:"Pk"`
  Sk             []byte `json:"Sk"`
}

// Sort client by name
// Using quichsort
func (s *Server) quickSort(low int, high int) {
	if low < high {
		i := low
		j := high
		pivot := s.Clients[low]

		for i < j {

			for i < j && s.Clients[j].ID >= pivot.ID {
				j--
			}
			if i < j {
				s.Clients[i] = s.Clients[j]
				i++
			}

			for i < j && s.Clients[i].ID < pivot.ID {
				i++
			}
			if i < j {
				s.Clients[j] = s.Clients[i]
				j--
			}
		}
		s.Clients[i] = pivot
		s.quickSort(low, i-1)
		s.quickSort(i+1, high)
	}
}

// add a client to current server
// search use linear search, could undate to binary search
func (s *Server) AddClient(c Client) {
	length := len(s.Clients)
	s.Clients = append(s.Clients, c)
	for i := 0; i <= length; i++ {
		if s.Clients[i].ID > s.Clients[length].ID {
			last := s.Clients[length]
			for j := length - 1; j >= i; j-- {
				s.Clients[j+1] = s.Clients[j]
			}
			s.Clients[i] = last
			break
		}
	}
}

// Using binary search to find a client
func (s Server) BinarySearch(client string, low int, high int) Client {
	mid := (low + high) / 2
	for low <= high {
		if s.Clients[mid].ID == client {
			return s.Clients[mid]
		} else if s.Clients[mid].ID < client {
			return s.BinarySearch(client, mid+1, high)
		} else if s.Clients[mid].ID >= client {
			return s.BinarySearch(client, low, mid-1)
		}
	}
	return Client{"", 0, ""}
}

// Count avg score of server
func (s *Server) CountScore() {
	var sum float32 = 0.0
	for _, client := range s.Clients {
		sum += float32(client.Score)
	}
	s.AvgScore = sum
}

// Get key from p256 
func (s *Server) GenerateKey() error{
  sk, pk := p256.GenerateKey()
  s.Pk = pk.ToByte()
  s.Sk = sk.ToByte()
  return nil
}

