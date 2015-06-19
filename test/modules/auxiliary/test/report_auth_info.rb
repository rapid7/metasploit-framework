##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  FAKE_IP   = '192.168.12.123'
  FAKE_PORT = 80
  FAKE_USER = 'username'
  FAKE_PASS = 'password'

  def initialize(info = {})
    super(update_info(info,
      'Name'           => "report_cred test",
      'Description'    => %q{
      	This module will test every auxiliary module's report_cred method
      },
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE
    ))
  end

  def test_novell_mdm_creds
    mod = framework.auxiliary.create('scanner/http/novell_mdm_creds')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_joomla_bruteforce_login
    mod = framework.auxiliary.create('scanner/http/joomla_bruteforce_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_infovista_enum
    mod = framework.auxiliary.create('scanner/http/infovista_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_etherpad_duo_login
    mod = framework.auxiliary.create('scanner/http/etherpad_duo_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_ektron_cms400net
    mod = framework.auxiliary.create('scanner/http/ektron_cms400net')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_drupal_views_user_enum
    mod = framework.auxiliary.create('scanner/http/drupal_views_user_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER)
  end

  def test_dolibarr_login
    mod = framework.auxiliary.create('scanner/http/dolibarr_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_dlink_dir_session_cgi_http_login
    mod = framework.auxiliary.create('scanner/http/dlink_dir_session_cgi_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_dlink_dir_615h_http_login
    mod = framework.auxiliary.create('scanner/http/dlink_dir_615h_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_dlink_dir_300_615_http_login
    mod = framework.auxiliary.create('scanner/http/dlink_dir_300_615_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_cisco_ssl_vpn
    mod = framework.auxiliary.create('scanner/http/cisco_ssl_vpn')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_cisco_ironport_enum
    mod = framework.auxiliary.create('scanner/http/cisco_ironport_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_cisco_asa_asdm
    mod = framework.auxiliary.create('scanner/http/cisco_asa_asdm')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_axis_local_file_include
    mod = framework.auxiliary.create('scanner/http/axis_local_file_include')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_splunk_web_login
    mod = framework.auxiliary.create('scanner/http/splunk_web_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_cctv_dvr_login
    mod = framework.auxiliary.create('scanner/misc/cctv_dvr_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_http_vcms_login
    mod = framework.auxiliary.create('scanner/http/vcms_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_telnet_ruggedcom
    mod = framework.auxiliary.create('scanner/telnet/telnet_ruggedcom')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: 'factory', password: FAKE_PASS)
  end

  def test_vmware_http_login
    mod = framework.auxiliary.create('scanner/vmware/vmware_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def test_asterisk_login
  	mod = framework.auxiliary.create('voip/asterisk_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS)
  end

  def run
    self.methods.each do |m|
      next if m.to_s !~ /^test_.+/
      print_status("Trying: ##{m.to_s}")
      begin
        self.send(m)
        print_good("That didn't blow up. Good!")
      rescue ::Exception => e
        print_error("That blew up :-(")
        print_line("#{e.class} #{e.message}\n#{e.backtrace*"\n"}")
      ensure
        print_line
      end
    end
  end

end
