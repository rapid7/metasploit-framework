##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Supermicro Onboard IPMI CGI Vulnerability Scanner',
      'Description' => %q{
        This module checks for known vulnerabilities in the CGI applications of
        Supermicro Onboard IPMI controllers. These issues currently include
        several unauthenticated buffer overflows in the login.cgi and close_window.cgi
        components.
      },
      'Author'       =>
        [
          'hdm', # Discovery and analysis
          'juan vazquez' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2013-3621' ],
          [ 'CVE', '2013-3623' ],
          [ 'URL', 'https://blog.rapid7.com/2013/11/06/supermicro-ipmi-firmware-vulnerabilities']
        ],
      'DisclosureDate' => 'Nov 06 2013'))

  end

  def is_supermicro?
    res = send_request_cgi(
      {
        "uri"       => "/",
        "method"    => "GET"
      })

    if res and res.code == 200 and res.body.to_s =~ /ATEN International Co Ltd\./
      return true
    else
      return false
    end
  end

  def send_close_window_request(sess)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => "/cgi/close_window.cgi",
      'encode_params' => false,
      'vars_post' => {
        'sess_sid' => sess
      }
    })

    return res
  end

  def check_close_window
    safe_check = Rex::Text.rand_text_alpha(20)
    trigger_check = Rex::Text.rand_text_alpha(132)

    res = send_close_window_request(safe_check)

    unless res and res.code == 200 and res.body.to_s =~ /Can't find action/
      return false
    end

    res = send_close_window_request(trigger_check)

    unless res and res.code == 500
      return false
    end

    return true
  end

  def send_login_request(name)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => "/cgi/login.cgi",
      'encode_params' => false,
      'vars_post' => {
       'name' => name,
       'pwd' => Rex::Text.rand_text_alpha(4)
      }
    })

    return res
  end


  def check_login
    safe_check = Rex::Text.rand_text_alpha(20)
    trigger_check = Rex::Text.rand_text_alpha(300)

    res = send_login_request(safe_check)

    unless res and res.code == 200 and res.body.to_s =~ /ATEN International Co Ltd\./ and res.body.to_s =~ /top\.location\.href = location\.href/
      return false
    end

    res = send_login_request(trigger_check)

    unless res and res.code == 500
      return false
    end

    return true
  end


  def run_host(ip)
    vprint_status("Checking if it's a Supermicro IPMI web interface...")
    if is_supermicro?
      vprint_good("Supermicro IPMI web interface found")
    else
      vprint_error("Supermicro IPMI web interface not found")
      return
    end

    vprint_status("Checking CVE-2013-3621 (login.gi Buffer Overflow) ...")
    result = check_login
    if result
      print_good("Vulnerable to CVE-2013-3621 (login.cgi Buffer Overflow)")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Supermicro Onboard IPMI login.cgi Buffer Overflow",
        :refs  => self.references.select do |ref| ref.ctx_val == "2013-3621" end
      })
    end

    vprint_status("Checking CVE-2013-3623 (close_window.gi Buffer Overflow) ...")
    result = check_close_window
    if result
      print_good("Vulnerable to CVE-2013-3623 (close_window.cgi Buffer Overflow)")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Supermicro Onboard IPMI close_window.cgi Buffer Overflow",
        :refs  => self.references.select { |ref| ref.ctx_val == "2013-3623" }
      })
    end

  end
end
