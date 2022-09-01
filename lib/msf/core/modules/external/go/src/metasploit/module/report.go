/*
 * Defines functions that report data to the core framework
 */

package module

import "log"

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

func ReportCredentialLogin(username string, password string, opts map[string]string) {
	base := map[string]string{"username": username, "password": password}
	if err := report("credential_login", base, opts); err != nil {
		log.Fatal(err)
	}
}

func report(kind string, base map[string]string, opts map[string]string) error {
	for k, v := range base {
		opts[k] = v
	}
	req := &reportRequest{"2.0", "report", reportparams{kind, opts}}
	return rpcSend(req)
}