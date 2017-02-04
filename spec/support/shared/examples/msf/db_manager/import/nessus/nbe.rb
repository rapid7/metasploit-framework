RSpec.shared_examples_for 'Msf::DBManager::Import::Nessus::NBE' do
  it { is_expected.to respond_to :import_nessus_nbe }
  it { is_expected.to respond_to :import_nessus_nbe_file }
end
