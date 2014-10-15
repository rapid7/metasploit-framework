shared_examples_for 'Msf::DBManager::Import' do
  it { is_expected.to respond_to :dehex }
  it { is_expected.to respond_to :emit }
  it { is_expected.to respond_to :import }
  it { is_expected.to respond_to :import_ci_noko_stream }
  it { is_expected.to respond_to :import_ci_xml }
  it { is_expected.to respond_to :import_file }
  it { is_expected.to respond_to :import_filetype_detect }
  it { is_expected.to respond_to :import_foundstone_noko_stream }
  it { is_expected.to respond_to :import_foundstone_xml }
  it { is_expected.to respond_to :import_fusionvm_xml }
  it { is_expected.to respond_to :import_ip_list }
  it { is_expected.to respond_to :import_ip_list_file }
  it { is_expected.to respond_to :import_libpcap }
  it { is_expected.to respond_to :import_libpcap_file }
  it { is_expected.to respond_to :import_mbsa_noko_stream }
  it { is_expected.to respond_to :import_mbsa_xml }
  it { is_expected.to respond_to :import_msf_collateral }
  it { is_expected.to respond_to :import_msf_cred_dump }
  it { is_expected.to respond_to :import_msf_cred_dump_zip }
  it { is_expected.to respond_to :import_msf_file }
  it { is_expected.to respond_to :import_msf_pwdump }
  it { is_expected.to respond_to :import_msf_zip }
  it { is_expected.to respond_to :import_nessus_nbe }
  it { is_expected.to respond_to :import_nessus_nbe_file }
  it { is_expected.to respond_to :import_nessus_xml }
  it { is_expected.to respond_to :import_nessus_xml_file }
  it { is_expected.to respond_to :import_nessus_xml_v2 }
  it { is_expected.to respond_to :import_netsparker_xml }
  it { is_expected.to respond_to :import_netsparker_xml_file }
  it { is_expected.to respond_to :import_nexpose_noko_stream }
  it { is_expected.to respond_to :import_nexpose_raw_noko_stream }
  it { is_expected.to respond_to :import_nexpose_rawxml }
  it { is_expected.to respond_to :import_nexpose_rawxml_file }
  it { is_expected.to respond_to :import_nexpose_simplexml }
  it { is_expected.to respond_to :import_nexpose_simplexml_file }
  it { is_expected.to respond_to :import_nikto_xml }
  it { is_expected.to respond_to :import_nmap_noko_stream }
  it { is_expected.to respond_to :import_nmap_xml }
  it { is_expected.to respond_to :import_nmap_xml_file }
  it { is_expected.to respond_to :import_openvas_new_xml }
  it { is_expected.to respond_to :import_openvas_new_xml_file }
  it { is_expected.to respond_to :import_openvas_xml }
  it { is_expected.to respond_to :import_outpost24_noko_stream }
  it { is_expected.to respond_to :import_outpost24_xml }
  it { is_expected.to respond_to :import_report }
  it { is_expected.to respond_to :import_retina_xml }
  it { is_expected.to respond_to :import_retina_xml_file }
  it { is_expected.to respond_to :import_spiceworks_csv }
  it { is_expected.to respond_to :import_wapiti_xml }
  it { is_expected.to respond_to :import_wapiti_xml_file }
  it { is_expected.to respond_to :inspect_single_packet }
  it { is_expected.to respond_to :inspect_single_packet_http }
  it { is_expected.to respond_to :msf_import_timestamps }
  it { is_expected.to respond_to :netsparker_method_map }
  it { is_expected.to respond_to :netsparker_params_map }
  it { is_expected.to respond_to :netsparker_pname_map }
  it { is_expected.to respond_to :netsparker_vulnerability_map }
  it { is_expected.to respond_to :nexpose_host_from_rawxml }
  it { is_expected.to respond_to :nexpose_refs_to_struct }
  it { is_expected.to respond_to :nils_for_nulls }
  it { is_expected.to respond_to :nmap_msf_service_map }
  it { is_expected.to respond_to :report_import_note }
  it { is_expected.to respond_to :rexmlify }
  it { is_expected.to respond_to :unserialize_object }
  it { is_expected.to respond_to :validate_import_file }

  it_should_behave_like 'Msf::DBManager::Import::Acunetix'
  it_should_behave_like 'Msf::DBManager::Import::Amap'
  it_should_behave_like 'Msf::DBManager::Import::Appscan'
  it_should_behave_like 'Msf::DBManager::Import::Burp'
  it_should_behave_like 'Msf::DBManager::Import::IP360'
  it_should_behave_like 'Msf::DBManager::Import::MsfXml'
  it_should_behave_like 'Msf::DBManager::Import::Qualys'
end