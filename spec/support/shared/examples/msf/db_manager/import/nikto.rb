RSpec.shared_examples_for 'Msf::DBManager::Import::Nikto' do
  it { is_expected.to respond_to :import_nikto_xml }
end
