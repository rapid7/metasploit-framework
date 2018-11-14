/*
 * Defines core functionality for a GOLANG module
 */

package module

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strings"
	"errors"
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

func ReportHost(ip string, opts map[string]string) {
	base := map[string]string{"host": ip}
	if err := report("host", base, opts); err != nil {
		log.Fatal(err)
	}
}

func ReportService(ip string, opts map[string]string) {
	base := map[string]string{"host": ip}
	if err := report("service", base, opts); err != nil {
		log.Fatal(err)
	}
}

func ReportVuln(ip string, name string, opts map[string]string) {
	base := map[string]string{"host": ip, "name": name}
	if err := report("vuln", base, opts); err != nil {
		log.Fatal(err)
	}
}

func ReportCorrectPassword(username string, password string, opts map[string]string) {
	base := map[string]string{"username": username, "password": password}
	if err := report("correct_password", base, opts); err != nil {
		log.Fatal(err)
	}
}

func ReportWrongPassword(username string, password string, opts map[string]string) {
	base := map[string]string{"username": username, "password": password}
	if err := report("wrong_password", base, opts); err != nil {
		log.Fatal(err)
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

func rpcSend(res interface{}) error {
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

func LogInfo(message string) {
	msfLog(message, "info")
}

func LogError(message string) {
	msfLog(message, "error")
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

func report(kind string, base map[string]string, opts map[string]string) error {
	for k, v := range base {
		opts[k] = v
	}
	req := &reportRequest{"2.0", "report", reportparams{kind, opts}}
	return rpcSend(req)
}