package dns

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

var params Parameters

func init() {
	ReadConfig()
}

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
	fmt.Println(params)
	if marshalErr != nil {
		fmt.Println("json Unmarshal failed")
		fmt.Println(marshalErr)
	}
	return marshalErr
}

func currentScore(traffic float32, clientScore float32, currentLevel float32) float32 {
	fmt.Println(params)
	// return traffic*cfg.Parameters.Alpha + clientScore*cfg.Parameters.Beta + currentLevel*cfg.Parameters.Gama
	return traffic*params.Cfg.Alpha + clientScore*params.Cfg.Beta + currentLevel*params.Cfg.Gama
}

