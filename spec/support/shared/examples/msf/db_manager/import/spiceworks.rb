RSpec.shared_examples_for 'Msf::DBManager::Import::Spiceworks' do
  it { is_expected.to respond_to :import_spiceworks_csv }
end
