package msmail

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"metasploit/module"
	"net/http"
	"strings"
	"time"
)

func WebRequestCodeResponse(URI string) int {
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
	}
	return resp.StatusCode
}

func HarvestInternalDomain(host string, outputDomain bool) string {
	if outputDomain {
		module.LogInfo("Attempting to harvest internal domain:")
	}
	url1 := "https://" + host + "/ews"
	url2 := "https://" + host + "/autodiscover/autodiscover.xml"
	url3 := "https://" + host + "/rpc"
	url4 := "https://" + host + "/mapi"
	url5 := "https://" + host + "/oab"
	url6 := "https://autodiscover." + host + "/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if WebRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if WebRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if WebRequestCodeResponse(url3) == 401 {
		urlToHarvest = url3
	} else if WebRequestCodeResponse(url4) == 401 {
		urlToHarvest = url4
	} else if WebRequestCodeResponse(url5) == 401 {
		urlToHarvest = url5
	} else if WebRequestCodeResponse(url6) == 401 {
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
	base64DecodedResp, err := base64.StdEncoding.DecodeString(data[1])
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
	if outputDomain {
		module.LogInfo("Internal Domain: ")
		module.LogInfo(string(internalDomainDecimal))
	}
	return string(internalDomainDecimal)
}

func ReportValidUsers(ip string, validUsers []string) {
	port := "443"
	service := "owa"
	protocol := "tcp"
	for _, user := range validUsers {
		opts := map[string]string{
			"port":         port,
			"service_name": service,
			"address":      ip,
			"protocol":     protocol,
		}
		module.LogInfo("Loging user: " + user)
		module.ReportCredentialLogin(user, "", opts)
	}
}

func WebRequestBasicAuth(URI string, user string, pass string, tr *http.Transport) int {
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

func ImportUserList(tempname string) []string {
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
