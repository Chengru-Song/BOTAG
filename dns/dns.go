package dns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"

	"github.com/GetALittleRough/BOTAG/vrf"
	"github.com/GetALittleRough/BOTAG/vrf/p256"
	"gonum.org/v1/gonum/stat/distuv"
)

// Current configuration files
type Config struct {
	Alpha float32 `json:"alpha"`
	Beta  float32 `json:"beta"`
	Gama  float32 `json:"gama"`
}

type Parameters struct {
	Cfg Config `json:"parameters"`
}

type Servers struct {
	SS          []Server
	TotalWeight float64
}

func (ss *Servers) SumWeight() float64 {
	var sum float32
	for _, s := range ss.SS {
		sum += s.Weight
	}
	ss.TotalWeight = float64(sum)
	return float64(sum)
}

var params Parameters

func init() {
	ReadConfig()
	// saveIdentity()
}

// Read configuration files about the parameters
func ReadConfig() error {

	// read the absolute path of configuration file
	path, configErr := filepath.Abs("./")
	if configErr != nil {
		fmt.Println("read configuration file failed")
		fmt.Println(configErr)
		return configErr
	}
	ConfigPath := filepath.Join(path, "../config.json")

	file, _ := os.Open(ConfigPath)
	defer file.Close()
	byteValue, _ := ioutil.ReadAll(file)

	// Read some configurations from file
	marshalErr := json.Unmarshal(byteValue, &params)
	if marshalErr != nil {
		fmt.Println("json Unmarshal failed")
		fmt.Println(marshalErr)
	}
	return marshalErr
}

// Save identity to file
func saveIdentity() error {
	sk, _ := p256.GenerateKey()
	err := sk.SaveParams()
	if err != nil {
		return err
	}
	return nil
}

// Read configuration file from local
func ReadIdentity(filename string) (vrf.PrivateKey, vrf.PublicKey) {
	sk := p256.ReadParams(filename)
	return sk, &p256.PublicKey{PublicKey: &sk.PublicKey}
}

// Calculate the score of a server
func currentScore(traffic float32, clientScore float32, currentLevel float32) float32 {
	fmt.Println(params)
	// return traffic*cfg.Parameters.Alpha + clientScore*cfg.Parameters.Beta + currentLevel*cfg.Parameters.Gama
	return traffic*params.Cfg.Alpha + clientScore*params.Cfg.Beta + currentLevel*params.Cfg.Gama
}

// Cryptographic sortition
func CryptographicSortition(hash [32]byte, N float64, P float64) int {
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

	binomial := distuv.Binomial{
		N: N,
		P: P,
	}

	for j := 0; j < int(N); j++ {
		if binomial.CDF(float64(j)) >= cratio {
			return j
		}
	}
	return int(N)
}

// Verify from a proof
func VerifyFromProof(ori [32]byte, m []byte, proof []byte, pk vrf.PublicKey, N float64, P float64, sj int) error {
	hash, err := pk.ProofToHash(m, proof)
	if err != nil {
		return err
	} else if hash != ori {
		return errors.New("Could not verify proof")
	}

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

	binomial := distuv.Binomial{
		N: N,
		P: P,
	}

	var J int = -1
	for j := 0; j < int(N); j++ {
		if binomial.CDF(float64(j)) >= cratio {
			J = j
			break
		}
	}

	if J == -1 {
		J = int(N)
	}
	if J != sj {
		return errors.New("error j provided")
	}

	return nil
}

// Read all servers from file
func ReadServers(filename string) (*Servers, error) {
	// read the absolute path of configuration file
	path, fileErr := filepath.Abs("./")
	if fileErr != nil {
		return nil, fileErr
	}
	ConfigPath := filepath.Join(path, filename)

	file, _ := os.Open(ConfigPath)
	defer file.Close()
	byteValue, _ := ioutil.ReadAll(file)

	var s []Server
	err := json.Unmarshal(byteValue, &s)
	if err != nil {
		return nil, err
	}
	var ss Servers
	ss.SS = s
	ss.SumWeight()
	return &ss, nil
}

// DNSResolve receives all current servers as Servers struct and the corresponding
// random number for the current round. DNSResolve verify the random number and
// select the current server for the requesting client
// BUG(=======Fri Feb 21 17:41:00 2020 Written by Chengru Song=======) should be
// aware that json.Unmarshal p256.PublicKey could not unmarshal the Curve pointer
// therefore created nil pointer in the struct, however the result is not infected
func DNSResolve(ss *Servers, proofs [][]byte, randoms []int, seed []byte, ms [][32]byte) (int, error) {
	total := ss.SumWeight()
	// Checks whether the server correspond to the proofs
	if len(ss.SS) != len(proofs) || len(ss.SS) != len(randoms) {
		return 0, errors.New("Wrong bytes or servers received")
	}

	var max, index int = 0, 0
	for i, s := range ss.SS {
		var pk p256.PublicKey
		//err := json.Unmarshal(s.Pk, &pk)
		//if err != nil {
		//  return 0, err
		//}
		json.Unmarshal(s.Pk, &pk)
		m := ms[i]
		proof := proofs[i]
		N := total
		P := float64(s.Weight) / total
		sj := randoms[i]
		var pk2 vrf.PublicKey
		pk2 = &pk
		verifyErr := VerifyFromProof(m, seed, proof, pk2, N, P, sj)
		if verifyErr != nil {
			return 0, verifyErr
		}
		if max < randoms[i] {
			max = randoms[i]
			index = i
		}
	}

	return index, nil
}

// Get public address of this server
func GetPublicIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", errors.New("Cannot get public IP")
}
