RSpec.shared_examples_for 'Msf::DBManager::Import' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting import ticket")}
  end

  it { is_expected.to respond_to :dehex }
  it { is_expected.to respond_to :emit }
  it { is_expected.to respond_to :import }
  it { is_expected.to respond_to :import_file }
  it { is_expected.to respond_to :import_filetype_detect }
  it { is_expected.to respond_to :msf_import_timestamps }
  it { is_expected.to respond_to :report_import_note }
  it { is_expected.to respond_to :rexmlify }
  it { is_expected.to respond_to :validate_import_file }

  it_should_behave_like 'Msf::DBManager::Import::Acunetix'
  it_should_behave_like 'Msf::DBManager::Import::Amap'
  it_should_behave_like 'Msf::DBManager::Import::Appscan'
  it_should_behave_like 'Msf::DBManager::Import::Burp'
  it_should_behave_like 'Msf::DBManager::Import::CI'
  it_should_behave_like 'Msf::DBManager::Import::Foundstone'
  it_should_behave_like 'Msf::DBManager::Import::FusionVM'
  it_should_behave_like 'Msf::DBManager::Import::GPP'
  it_should_behave_like 'Msf::DBManager::Import::IP360'
  it_should_behave_like 'Msf::DBManager::Import::IPList'
  it_should_behave_like 'Msf::DBManager::Import::Libpcap'
  it_should_behave_like 'Msf::DBManager::Import::MBSA'
  it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework'
  it_should_behave_like 'Msf::DBManager::Import::Nessus'
  it_should_behave_like 'Msf::DBManager::Import::Netsparker'
  it_should_behave_like 'Msf::DBManager::Import::Nexpose'
  it_should_behave_like 'Msf::DBManager::Import::Nikto'
  it_should_behave_like 'Msf::DBManager::Import::Nmap'
  it_should_behave_like 'Msf::DBManager::Import::OpenVAS'
  it_should_behave_like 'Msf::DBManager::Import::Outpost24'
  it_should_behave_like 'Msf::DBManager::Import::Qualys'
  it_should_behave_like 'Msf::DBManager::Import::Report'
  it_should_behave_like 'Msf::DBManager::Import::Retina'
  it_should_behave_like 'Msf::DBManager::Import::Spiceworks'
  it_should_behave_like 'Msf::DBManager::Import::Wapiti'
end
