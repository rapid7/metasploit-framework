RSpec.shared_examples_for 'Msf::DBManager::Import::IPList' do
  it { is_expected.to respond_to :import_ip_list }
  it { is_expected.to respond_to :import_ip_list_file }
end
