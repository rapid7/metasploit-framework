package metasploit

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
)

type response struct {
	Jsonrpc string `json:"jsonrpc"`
	Id string      `json:"id"`
}

func rpc_send(res interface{}) {
	res_str, _ := json.Marshal(res)
	f := bufio.NewWriter(os.Stdout)
	defer f.Flush()
	f.Write(res_str)
}

type (
	logparams struct {
		Level string `json:"level"`
		Message string `json:"message"`
	}

	LogRequest struct {
		Jsonrpc string `json:"jsonrpc"`
		Method string  `json:"method"`
		Params logparams `json:"params"`
	}

)

// 'debug'
func Log(message string, level string) {
	req := &LogRequest {"2.0", "message", logparams{level, message}}
	rpc_send(req)
}

type (
	reportparams struct {
		Type string `json:"type"`
		Data map[string]string `json:"data"`
	}

	ReportRequest struct {
		Jsonrpc string `json:"jsonrpc"`
		Method string  `json:"method"`
		Params reportparams `json:"params"`
	}
)

func report(kind string, base map[string]string, opts map[string]string) {
	for k, v := range base {
		opts[k] = v
	}
	req := &ReportRequest {"2.0", "report", reportparams{kind, opts}}
	rpc_send(req)
}

func ReportHost(ip string, opts map[string]string) {
	base := map[string]string{"host": ip}
	report("host", base, opts)
}

func ReportService(ip string, opts map[string]string) {
	base := map[string]string{"host": ip}
	report("service", base, opts)
}

func ReportVuln(ip string, name string, opts map[string]string) {
	base := map[string]string{"host": ip, "name": name}
	report("vuln", base, opts)
}

func ReportCorrectPassword(username string, password string, opts map[string]string) {
	base := map[string]string{"username": username, "password": password}
	report("correct_password", base, opts)
}

func ReportWrongPassword(username string, password string, opts map[string]string) {
	base := map[string]string{"username": username, "password": password}
	report("wrong_password", base, opts)
}

type (
	Reference struct {
		Type string `json:"type"`
		Ref string `json:"ref"`
	}

	Target struct {
		Platform string `json:"platform"`
		Arch string `json:"arch"`
	}

	Option struct {
		Type string `json:"type"`
		Description string `json:"description"`
		Required bool `json:"required"`
		Default string `json:"default"`
	}

	Metadata struct {
		Name string `json:"name"`
		Description string `json:"description"`
		Authors []string `json:"authors"`
		Date string `json:"date"`
		References []Reference `json:"references"`
		Type string `json:"type"`
		Rank string `json:"rank"`
		WFSDelay int `json:"wfsdelay"`
		Privileged bool `json:"privileged"`
		Targets []Target `json:"targets",omitempty`
		Capabilities []string `json:"capabilities"`
		Payload map[string]string `json:"payload",omitempty`
		Options map[string]Option `json:"options",omitempty`
		Notes map[string][]string `json:"notes",omitempty`
    }

	Request struct {
		Jsonrpc string `json:"jsonrpc"`
		Method string `json:"method"`
		Id string `json:"id"`
	}

	MetadataResponse struct {
		Jsonrpc string `json:"jsonrpc"`
		Id string  `json:"id"`
		Result *Metadata `json:"result"`
	}

	RunResult struct {
		Message string `json:"message"`
		Return string `json:"return"`
	}

	RunResponse struct {
		Jsonrpc string `json:"jsonrpc"`
		Id string  `json:"id"`
		Result RunResult `json:"result"`
	}
)

type RunCallback func(req *Request) string

func Run(metadata *Metadata, callback RunCallback) {
	var req Request

	err := json.NewDecoder(os.Stdin).Decode(&req)
	if err != nil {
		log.Fatal(err)
	}
	if req.Method == "describe" {
		metadata.Capabilities = []string{"run"}
		res := &MetadataResponse{"2.0", req.Id, metadata}
		rpc_send(res)
	}

	if req.Method == "run" {
		ret := callback(&req)
		res := &RunResponse{"2.0", req.Id, RunResult{"Module complete", ret}}
		rpc_send(res)
	}
}
/*
	//type RunCallback func(struct) string
    def run(metadata, callback, soft_check: nil)
      elsif req[:method] == 'run'
        cb = callback
      end

      if cb
        ret = cb.call req[:params]
        rpc_send({
          jsonrpc: '2.0', id: req[:id], result: {
            message: 'Module completed',
            'return' => ret
          }
        })
      end
*/
//}
