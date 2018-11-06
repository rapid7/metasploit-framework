package metasploit

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strings"
)

type response struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      string `json:"id"`
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

func Log(message string, level string) {
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
	Reference struct {
		Type string `json:"type"`
		Ref  string `json:"ref"`
	}

	Target struct {
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
	}

	Option struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Required    bool   `json:"required"`
		Default     string `json:"default"`
	}

	Metadata struct {
		Name         string              `json:"name"`
		Description  string              `json:"description"`
		Authors      []string            `json:"authors"`
		Date         string              `json:"date"`
		References   []Reference         `json:"references"`
		Type         string              `json:"type"`
		Rank         string              `json:"rank"`
		WFSDelay     int                 `json:"wfsdelay"`
		Privileged   bool                `json:"privileged"`
		Targets      []Target            `json:"targets,omitempty"`
		Capabilities []string            `json:"capabilities"`
		Payload      map[string]string   `json:"payload,omitempty"`
		Options      map[string]Option   `json:"options,omitempty"`
		Notes        map[string][]string `json:"notes,omitempty"`
	}

	Request struct {
		Jsonrpc string `json:"jsonrpc"`
		Method  string `json:"method"`
		ID      string `json:"id"`
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
)

// RunCallback represents the exploit method to call from the module
type RunCallback func(req *Request) string

// Run runs the exploit
func Run(metadata *Metadata, callback RunCallback) {
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
		ret := callback(&req)
		res := &RunResponse{"2.0", req.ID, RunResult{"Module complete", ret}}
		if err := rpcSend(res); err != nil {
			log.Fatalf("error on running %s: %v", req.Method, err)
		}
	default:
		log.Fatalf("method %s not implemented yet", req.Method)
	}
}
