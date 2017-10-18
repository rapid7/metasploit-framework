##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  FAKE_IP    = '192.168.12.123'
  FAKE_PORT  = 80
  FAKE_USER  = 'user'
  FAKE_PASS  = 'password'
  FAKE_PROOF = 'proof'

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
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_joomla_bruteforce_login
    mod = framework.auxiliary.create('scanner/http/joomla_bruteforce_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_infovista_enum
    mod = framework.auxiliary.create('scanner/http/infovista_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_etherpad_duo_login
    mod = framework.auxiliary.create('scanner/http/etherpad_duo_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_ektron_cms400net
    mod = framework.auxiliary.create('scanner/http/ektron_cms400net')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_drupal_views_user_enum
    mod = framework.auxiliary.create('scanner/http/drupal_views_user_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, proof: FAKE_PROOF)
  end

  def test_dolibarr_login
    mod = framework.auxiliary.create('scanner/http/dolibarr_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dlink_dir_session_cgi_http_login
    mod = framework.auxiliary.create('scanner/http/dlink_dir_session_cgi_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dlink_dir_615h_http_login
    mod = framework.auxiliary.create('scanner/http/dlink_dir_615h_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dlink_dir_300_615_http_login
    mod = framework.auxiliary.create('scanner/http/dlink_dir_300_615_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_cisco_ssl_vpn
    mod = framework.auxiliary.create('scanner/http/cisco_ssl_vpn')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_cisco_ironport_enum
    mod = framework.auxiliary.create('scanner/http/cisco_ironport_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_cisco_asa_asdm
    mod = framework.auxiliary.create('scanner/http/cisco_asa_asdm')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_axis_local_file_include
    mod = framework.auxiliary.create('scanner/http/axis_local_file_include')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_splunk_web_login
    mod = framework.auxiliary.create('scanner/http/splunk_web_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_cctv_dvr_login
    mod = framework.auxiliary.create('scanner/misc/cctv_dvr_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_http_vcms_login
    mod = framework.auxiliary.create('scanner/http/vcms_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_telnet_ruggedcom
    mod = framework.auxiliary.create('scanner/telnet/telnet_ruggedcom')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: 'factory', password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_vmware_http_login
    mod = framework.auxiliary.create('scanner/vmware/vmware_http_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_asterisk_login
    mod = framework.auxiliary.create('voip/asterisk_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_hp_imc_som_create_account
    mod = framework.auxiliary.create('admin/hp/hp_imc_som_create_account')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'https', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dlink_dir_645_password_extractor
    mod = framework.auxiliary.create('admin/http/dlink_dir_645_password_extractor')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dlink_dsl320b_password_extractor
    mod = framework.auxiliary.create('admin/http/dlink_dsl320b_password_extractor')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF )
  end

  def test_nexpose_xxe_file_read
    mod = framework.auxiliary.create('admin/http/nexpose_xxe_file_read')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_vbulletin_upgrade_admin
    mod = framework.auxiliary.create('admin/http/vbulletin_upgrade_admin')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_wp_custom_contact_forms
    mod = framework.auxiliary.create('admin/http/wp_custom_contact_forms')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, service_name: 'WordPress', proof: FAKE_PROOF)
  end

  def test_zyxel_admin_password_extractor
    mod = framework.auxiliary.create('admin/http/zyxel_admin_password_extractor')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'ZyXEL GS1510-16', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_sercomm_dump_config
    mod = framework.auxiliary.create('admin/misc/sercomm_dump_config')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, user: FAKE_USER, password: FAKE_PASS, service_name: 'sercomm', proof: FAKE_PROOF)
  end

  def test_vnc
    mod = framework.auxiliary.create('server/capture/vnc')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'vnc_client', user: '', password: FAKE_PASS, proof: FAKE_PROOF )
  end

  def test_smtp
    mod = framework.auxiliary.create('server/capture/smtp')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'pop3', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_sip
    mod = framework.auxiliary.create('server/capture/sip')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'sip_client', user:FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_oracle_login
    mod = framework.auxiliary.create('admin/oracle/oracle_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'oracle', user: FAKE_USER, password: FAKE_PASS )
  end

  def test_postgresql
    mod = framework.auxiliary.create('server/capture/postgresql')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'psql_client', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_pop3
    mod = framework.auxiliary.create('server/capture/pop3')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'pop3', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF )
  end

  def test_http_basic
    mod = framework.auxiliary.create('server/capture/http_basic')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'HTTP', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF )
  end

  def test_ftp
    mod = framework.auxiliary.create('server/capture/ftp')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'ftp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_drda
    mod = framework.auxiliary.create('server/capture/drda')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'db2_client', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_koyo_login
    mod = framework.auxiliary.create('scanner/scada/koyo_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'koyo', user: '', password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_openvas_otp_login
    mod = framework.auxiliary.create('scanner/openvas/openvas_otp_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'openvas-otp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_openvas_omp_login
    mod = framework.auxiliary.create('scanner/openvas/openvas_omp_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'openvas-omp', user: FAKE_USER, password: FAKE_PASS, proof: @result)
  end

  def test_openvas_gsad_login
    mod = framework.auxiliary.create('scanner/openvas/openvas_gsad_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'openvas-gsa', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_nexpose_api_login
    mod = framework.auxiliary.create('scanner/nexpose/nexpose_api_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'nexpose', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_nessus_ntp_login
    mod = framework.auxiliary.create('scanner/nessus/nessus_ntp_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'nessus-ntp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_msf_web_login
    mod = framework.auxiliary.create('scanner/msf/msf_web_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'msf-web', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_msf_rpc_login
    mod = framework.auxiliary.create('scanner/msf/msf_rpc_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'msf-rpc', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF )
  end

  def test_mongodb_login
    mod = framework.auxiliary.create('scanner/mongodb/mongodb_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'mongodb', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_rosewill_rxs3211_passwords
    mod = framework.auxiliary.create('scanner/misc/rosewill_rxs3211_passwords')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'ipcam', user: '', password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_raysharp_dvr_passwords
    mod = framework.auxiliary.create('scanner/misc/raysharp_dvr_passwords')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'dvr', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_oki_scanner
    mod = framework.auxiliary.create('scanner/misc/oki_scanner')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dvr_config_disclosure
    mod = framework.auxiliary.create('scanner/misc/dvr_config_disclosure')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'ftp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_typo3_bruteforce
    mod = framework.auxiliary.create('scanner/http/typo3_bruteforce')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'typo3', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_squiz_matrix_user_enum
    mod = framework.auxiliary.create('scanner/http/squiz_matrix_user_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', proof: FAKE_PROOF)
  end

  def test_sevone_enum
    mod = framework.auxiliary.create('scanner/http/sevone_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: '') 
  end

  def test_sentry_cdu_enum
    mod = framework.auxiliary.create('scanner/http/sentry_cdu_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_sap_businessobjects_user_brute_web
    mod = framework.auxiliary.create('scanner/http/sap_businessobjects_user_brute_web')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'sap-businessobjects', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_sap_businessobjects_user_brute
    mod = framework.auxiliary.create('scanner/http/sap_businessobjects_user_brute')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'sap-businessobjects', user: FAKE_USER, proof: FAKE_PROOF)
  end

  def test_rfcode_reader_enum
    mod = framework.auxiliary.create('scanner/http/rfcode_reader_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'RFCode Reader', user: FAKE_USER, password:FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_radware_appdictor_enum
    mod = framework.auxiliary.create('scanner/http/radware_appdirector_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'Radware AppDirector', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_pocketpad_login
    mod = framework.auxiliary.create('scanner/http/pocketpad_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'PocketPAD Portal', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_oracle_ilom_login
    mod = framework.auxiliary.create('scanner/http/oracle_ilom_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'Oracle Integrated Lights Out Manager Portal', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_mysql
    mod = framework.auxiliary.create('server/capture/mysql')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'mysql_client', user: FAKE_USER, pass: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_http
    mod = framework.auxiliary.create('server/capture/http')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, pass: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_ssh_enumusers
    mod = framework.auxiliary.create('scanner/ssh/ssh_enumusers')
    mod.do_report(FAKE_IP, FAKE_USER, FAKE_PORT)
  end

  def test_cerberus_sftp_enumusers
    mod = framework.auxiliary.create('scanner/ssh/cerberus_sftp_enumusers')
    mod.do_report(FAKE_IP, FAKE_USER, FAKE_PORT)
  end

  def test_sap_web_gui_brute_login
    mod = framework.auxiliary.create('scanner/sap/sap_web_gui_brute_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'sap_webgui', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_sap_soap_rfc_brute_login
    mod = framework.auxiliary.create('scanner/sap/sap_soap_rfc_brute_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'sap', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_sap_soap_bapi_user_create1
    mod = framework.auxiliary.create('scanner/sap/sap_soap_bapi_user_create1')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'sap', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_mount_cifs_creds
    mod = framework.post.create('linux/gather/mount_cifs_creds')
    mock_post_mod_session(mod)
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'smb', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_mysql_enum
    mod = framework.auxiliary.create('admin/mysql/mysql_enum')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'mysql', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_jtr_oracle_fast
    mod = framework.auxiliary.create('analyze/jtr_oracle_fast')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'oracle', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_vbulletin_vote_sqli_exec
    mod = framework.exploits.create('unix/webapp/vbulletin_vote_sqli_exec')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)    
  end

  def test_sap_mgmt_con_brute_login
    mod = framework.auxiliary.create('scanner/sap/sap_mgmt_con_brute_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_sap_ctc_verb_tampering_user_mgmt
    mod = framework.auxiliary.create('scanner/sap/sap_ctc_verb_tampering_user_mgmt')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_scanner_oracle_login
    mod = framework.auxiliary.create('scanner/oracle/oracle_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'tcp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF, status: Metasploit::Model::Login::Status::SUCCESSFUL)
  end

  def test_isqlplus_login
    mod = framework.auxiliary.create('scanner/oracle/isqlplus_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'tcp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dvr_config_disclosure
    mod = framework.auxiliary.create('scanner/misc/dvr_config_disclosure')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_lotus_domino_login
    mod = framework.auxiliary.create('scanner/lotus/lotus_domino_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_openmind_messageos_login
    mod = framework.auxiliary.create('scanner/http/openmind_messageos_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_dell_idrac
    mod = framework.auxiliary.create('scanner/http/dell_idrac')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_windows_deployment_services
    mod = framework.auxiliary.create('scanner/dcerpc/windows_deployment_services')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'dcerpc', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_couchdb_login
    mod = framework.auxiliary.create('scanner/couchdb/couchdb_login')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'couchdb', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_wp_w3_total_cache_hash_extract
    mod = framework.auxiliary.create('gather/wp_w3_total_cache_hash_extract')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_windows_deployment_services_shares
    mod = framework.auxiliary.create('gather/windows_deployment_services_shares')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'smb', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_vbulletin_vote_sqli
    mod = framework.auxiliary.create('gather/vbulletin_vote_sqli')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_hp_snac_domain_creds
    mod = framework.auxiliary.create('gather/hp_snac_domain_creds')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'hp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_d20pass
     mod = framework.auxiliary.create('gather/d20pass')
     mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'hp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_doliwamp_traversal_creds
    mod = framework.auxiliary.create('gather/doliwamp_traversal_creds')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'hp', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_apache_rave_creds
    mod = framework.auxiliary.create('gather/apache_rave_creds')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'Apache Rave', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_wordpress_long_password_dos
    mod = framework.auxiliary.create('dos/http/wordpress_long_password_dos')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, proof: FAKE_PROOF)
  end

  def test_modicon_password_recovery
    mod = framework.auxiliary.create('admin/scada/modicon_password_recovery')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def test_advantech_webaccess_dbvisitor_sqli
    mod = framework.auxiliary.create('admin/scada/advantech_webaccess_dbvisitor_sqli')
    mod.report_cred(ip: FAKE_IP, port: FAKE_PORT, service_name: 'http', user: FAKE_USER, password: FAKE_PASS, proof: FAKE_PROOF)
  end

  def run
    counter_all  = 0
    counter_good = 0
    counter_bad = 0
    self.methods.each do |m|
      next if m.to_s !~ /^test_.+/
      print_status("Trying: ##{m.to_s}")
      begin
        self.send(m)
        print_good("That didn't blow up. Good!")
        counter_good += 1
      rescue ::Exception => e
        print_error("That blew up :-(")
        print_line("#{e.class} #{e.message}\n#{e.backtrace*"\n"}")
        counter_bad += 1
      ensure
        print_line
      end

      counter_all += 1
    end

    print_good("Number of test cases that passed: #{counter_good}")
    print_error("Number of test cases that failed: #{counter_bad}")
    print_status("Number of test cases overall: #{counter_all}")
    print_line
  end

  def mock_post_mod_session(mod)
    mod.define_singleton_method(:session_db_id) { 1 }
  end

end
