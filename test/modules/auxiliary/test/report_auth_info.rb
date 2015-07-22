##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  FAKE_IP   = '192.168.12.123'
  FAKE_PORT = 80
  FAKE_USER = 'user'
  FAKE_PASS = 'password'

  def initialize(info = {})
    super(update_info(info,
      'Name'           => "report_cred Test",
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

  def test_hp_imc_som_create_account
    mod = framework.auxiliary.create('admin/hp/hp_imc_som_create_account')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'https',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_dlink_dir_645_password_extractor
    mod = framework.auxiliary.create('admin/http/dlink_dir_645_password_extractor')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'http',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_dlink_dsl320b_password_extractor
    mod = framework.auxiliary.create('admin/http/dlink_dsl320b_password_extractor')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'http',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_nexpose_xxe_file_read
    mod = framework.auxiliary.create('admin/http/nexpose_xxe_file_read')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'http',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_vbulletin_upgrade_admin
    mod = framework.auxiliary.create('admin/http/vbulletin_upgrade_admin')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'http',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_wp_custom_contact_forms
    mod = framework.auxiliary.create('admin/http/wp_custom_contact_forms')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      user: FAKE_USER,
      password: FAKE_PASS,
      service_name: 'WordPress',
      proof: ''
    )
  end

  def test_zyxel_admin_password_extractor
    mod = framework.auxiliary.create('admin/http/zyxel_admin_password_extractor')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'ZyXEL GS1510-16',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_sercomm_dump_config
    mod = framework.auxiliary.create('admin/misc/sercomm_dump_config')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      user: FAKE_USER,
      password: FAKE_PASS,
      service_name: 'sercomm',
      proof: ''
    )
  end

  def test_vnc
    mod = framework.auxiliary.create('server/capture/vnc')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'vnc_client',
      user: '',
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_smtp
    mod = framework.auxiliary.create('server/capture/smtp')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'pop3',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_sip
    mod = framework.auxiliary.create('server/capture/sip')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'sip_client',
      user:FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_oracle_login
    mod = framework.auxiliary.create('admin/oracle/oracle_login')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'oracle',
      user: FAKE_USER,
      password: FAKE_PASS
    )
  end

  def test_postgresql
    mod = framework.auxiliary.create('server/capture/postgresql')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'psql_client',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_pop3
    mod = framework.auxiliary.create('server/capture/pop3')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'pop3',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_http_basic
    mod = framework.auxiliary.create('server/capture/http_basic')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'HTTP',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_ftp
    mod = framework.auxiliary.create('server/capture/ftp')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'ftp',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_drda
    mod = framework.auxiliary.create('server/capture/drda')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'db2_client',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_koyo_login
    mod = framework.auxiliary.create('scanner/scada/koyo_login')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'koyo',
      user: '',
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_openvas_otp_login
    mod = framework.auxiliary.create('scanner/openvas/openvas_otp_login')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'openvas-otp',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_openvas_omp_login
    mod = framework.auxiliary.create('scanner/openvas/openvas_omp_login')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'openvas-omp',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: @result
    )
  end

  def test_openvas_gsad_login
    mod = framework.auxiliary.create('scanner/openvas/openvas_gsad_login')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'openvas-gsa',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
  end

  def test_nexpose_api_login
    mod = framework.auxiliary.create('scanner/nexpose/nexpose_api_login')
    mod.report_cred(
      ip: FAKE_IP,
      port: FAKE_PORT,
      service_name: 'nexpose',
      user: FAKE_USER,
      password: FAKE_PASS,
      proof: ''
    )
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
