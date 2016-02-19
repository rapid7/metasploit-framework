RSpec.shared_examples_for 'Msf::DBManager::Import::FusionVM' do
  it { is_expected.to respond_to :import_fusionvm_xml }
end
