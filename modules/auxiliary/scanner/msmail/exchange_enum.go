//usr/bin/env go run "$0" "$@"; exit "$?"

package main

import (
	"crypto/tls"
	"fmt"
	"metasploit/module"
	"msmail"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

func main() {
	metadata := &module.Metadata{
		Name:        "Exchange email enumeration",
		Description: "Error-based user enumeration for Office 365 integrated email addresses",
		Authors:     []string{"poptart", "jlarose", "Vincent Yiu", "grimhacker", "Nate Power", "Nick Powers", "clee-r7"},
		Date:        "2018-11-06",
		Type:        "single_scanner",
		Privileged:  false,
		References:  []module.Reference{},
		Options: map[string]module.Option{
			"RHOSTS":     {Type: "string", Description: "Target endpoint", Required: true, Default: "outlook.office365.com"},
			"EMAIL":      {Type: "string", Description: "Single email address to do identity test against", Required: false, Default: ""},
			"EMAIL_FILE": {Type: "string", Description: "Path to file containing list of email addresses", Required: false, Default: ""},
		}}

	module.Init(metadata, run_exchange_enum)
}

func run_exchange_enum(params map[string]interface{}) {
	email := params["EMAIL"].(string)
	emailFile := params["EMAIL_FILE"].(string)
	threads, e := strconv.Atoi(params["THREADS"].(string))
	ip := params["rhost"].(string)

	if e != nil {
		module.LogError("Unable to parse 'Threads' value using default (5)")
		threads = 5
	}

	if threads > 100 {
		module.LogInfo("Threads value too large, setting max(100)")
		threads = 100
	}

	if email == "" && emailFile == "" {
		module.LogError("Expected 'EMAIL' or 'EMAIL_FILE' field to be populated")
		return
	}

	var validUsers []string
	if email != "" {
		validUsers = o365enum(ip, []string{email}, threads)
	}

	if emailFile != "" {
		validUsers = o365enum(ip, msmail.ImportUserList(emailFile), threads)
	}

	msmail.ReportValidUsers(ip, validUsers)
}

func o365enum(ip string, emaillist []string, threads int) []string {
	limit := threads
	var wg sync.WaitGroup
	queue := make(chan string)
	//limit := 100

	/*Keep in mind you, nothing has been added to handle successful auths
	  so the password for auth attempts has been hardcoded to something
	  that is not likely to be correct.
	*/
	pass := "Summer2018876"
	URI := "https://" + ip + "/Microsoft-Server-ActiveSync"
	var validemails []string

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for email := range queue {
				responseCode := msmail.WebRequestBasicAuth(URI, email, pass, tr)
				if strings.Contains(email, "@") && responseCode == 401 {
					module.LogGood(email + " - 401")
					validemails = append(validemails, email)
				} else if strings.Contains(email, "@") && responseCode == 404 {
					module.LogError(fmt.Sprintf("%s - %d", email, responseCode))
				} else {
					module.LogError(fmt.Sprintf("Unusual Response: %s - %d", email, responseCode))
				}
			}
		}(i)
	}

	for i := 0; i < len(emaillist); i++ {
		queue <- emaillist[i]
	}

	close(queue)
	wg.Wait()
	return validemails
}
