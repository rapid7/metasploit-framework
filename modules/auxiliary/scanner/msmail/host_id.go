//usr/bin/env go run "$0" "$@"; exit "$?"

/*
 OWA (Outlook Webapp) is vulnerable to time-based user enumeration attacks.
 This module leverages all known, and even some lesser-known services exposed by default
 Exchange installations to enumerate users. It also targets Office 365 for error-based user enumeration.

 Used for gathering information about a host that may be pointed towards an Exchange or o365 tied domain
 Queries for specific DNS records related to Office 365 integration
 Attempts to extract internal domain name for onprem instance of Exchange
 Identifies services vulnerable to time-based user enumeration for onprem Exchange
 Lists password-sprayable services exposed for onprem Exchange host
*/
package main

import (
	"metasploit/module"
	"msmail"
	"net"
	"strings"
)

func main() {
	metadata := &module.Metadata{
		Name:        "msmail_ident",
		Description: "Office 365 and Exchange Enumeration",
		Authors:     []string{"poptart", "jlarose", "Vincent Yiu", "grimhacker", "Nate Power", "Nick Powers", "clee-r7"},
		Date:        "2018-11-06",
		Type:        "single_scanner",
		Privileged:  false,
		References:  []module.Reference{},
		Options:     map[string]module.Option{},
	}

	module.Init(metadata, run_id)
}

func run_id(params map[string]interface{}) {
	host := params["RHOSTS"].(string)
	msmail.HarvestInternalDomain(host, true)
	urlEnum(host)
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
		responseCode := msmail.WebRequestCodeResponse(uri)
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
		responseCode := msmail.WebRequestCodeResponse(uri)
		if responseCode == 401 {
			module.LogInfo("[+] " + uri)
			passEndpointIdentified = true
		}
	}
	ecpURI := "https://" + hostInput + "/ecp"
	endpoints200 := []string{ecpURI, owaURI}
	for _, uri := range endpoints200 {
		responseCode := msmail.WebRequestCodeResponse(uri)
		if responseCode == 200 {
			module.LogInfo("[+] " + uri)
			passEndpointIdentified = true
		}
	}
	if passEndpointIdentified == false {
		module.LogInfo("No onprem Exchange services identified.")
	}
}
