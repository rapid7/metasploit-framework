/*
 * Defines core functionality for a GOLANG module
 */

package module

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
)

/*
 * RunCallback represents the method to call from the module
 */
type RunCallback func(params map[string]interface{})

/*
 * Initializes the module waiting for input from stdin
 */
func Init(metadata *Metadata, callback RunCallback) {
	var req Request

	err := json.NewDecoder(os.Stdin).Decode(&req)
	if err != nil {
		log.Fatalf("could not decode JSON: %v", err)
	}

	switch strings.ToLower(req.Method) {
	case "describe":
		metadata.Capabilities = []string{"run"}
		res := &MetadataResponse{"2.0", req.ID, metadata}
		if err := rpcSend(res); err != nil {
			log.Fatalf("error on running %s: %v", req.Method, err)
		}
	case "run":
		params, e := parseParams(req.Parameters)
		if e != nil {
			log.Fatal(e)
		}
		callback(params)
		res := &RunResponse{"2.0", req.ID, RunResult{"Module complete", ""}}
		if err := rpcSend(res); err != nil {
			log.Fatalf("error on running %s: %v", req.Method, err)
		}
	default:
		log.Fatalf("method %s not implemented yet", req.Method)
	}
}

type (
	Request struct {
		Jsonrpc string `json:"jsonrpc"`
		Method  string `json:"method"`
		ID      string `json:"id"`
		Parameters interface{} `json:"params"`
	}

	MetadataResponse struct {
		Jsonrpc string    `json:"jsonrpc"`
		ID      string    `json:"id"`
		Result  *Metadata `json:"result"`
	}

	RunResult struct {
		Message string `json:"message"`
		Return  string `json:"return"`
	}

	RunResponse struct {
		Jsonrpc string    `json:"jsonrpc"`
		ID      string    `json:"id"`
		Result  RunResult `json:"result"`
	}

	Parameters struct {
		Type string `json:"type"`
		Description string `json:"description"`
		Required bool `json:"required"`
		Default interface{} `json:"default"`
	}
)

type response struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      string `json:"id"`
}

func parseParams(passedParams interface{}) (map[string]interface{}, error) {
	v, ok := passedParams.(map[string]interface{})
	if !ok {
		return nil, errors.New("cannot parse values")
	}

	return v, nil
}

var rpcMutex = &sync.Mutex{}

func rpcSend(res interface{}) error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	resStr, err := json.Marshal(res)
	if err != nil {
		return err
	}
	f := bufio.NewWriter(os.Stdout)
	if _, err := f.Write(resStr); err != nil {
		return err
	}
	if err := f.Flush(); err != nil {
		return err
	}

	return nil
}

type (
	logparams struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	}

	logRequest struct {
		Jsonrpc string    `json:"jsonrpc"`
		Method  string    `json:"method"`
		Params  logparams `json:"params"`
	}
)

func LogError(message string) {
	msfLog(message, "error")
}

func LogWarning(message string) {
	msfLog(message, "warning")
}

func LogGood(message string) {
	msfLog(message, "good")
}

func LogInfo(message string) {
	msfLog(message, "info")
}

func LogDebug(message string) {
	msfLog(message, "debug")
}

func msfLog(message string, level string) {
	req := &logRequest{"2.0", "message", logparams{level, message}}
	if err := rpcSend(req); err != nil {
		log.Fatal(err)
	}
}

type (
	reportparams struct {
		Type string            `json:"type"`
		Data map[string]string `json:"data"`
	}

	reportRequest struct {
		Jsonrpc string       `json:"jsonrpc"`
		Method  string       `json:"method"`
		Params  reportparams `json:"params"`
	}
)
