package dns

import (
	"testing"
)

func TestQuickSort(t *testing.T) {
	t.Log("quick sort test")
	s := Server{
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
	}
	t.Log(s)
	s.quickSort(0, len(s.Clients)-1)
	t.Log(s)
}

func TestAddClient(t *testing.T) {
	t.Log("testing add client")
	c := Client{
		ID:           "tu",
		Score:        3,
		CurrentProxy: "123.23.1.2",
	}
	s := Server{
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
	}
	s.quickSort(0, len(s.Clients)-1)
	s.AddClient(c)
	t.Log(s)
}

func TestBinarySearch(t *testing.T) {

	s := Server{
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
	}
	s.quickSort(0, len(s.Clients)-1)
	result := s.BinarySearch("au", 0, len(s.Clients)-1)
	if result.ID != "au" {
		t.Fatal("binary search failed")
	}
}

func TestCountScore(t *testing.T) {

	s := Server{
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
	}
	s.CountScore()
	t.Log(s.AvgScore)
}
