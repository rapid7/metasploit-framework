RSpec.shared_examples_for 'Msf::DBManager::Import::Report' do
  it { is_expected.to respond_to :import_report }
end
