RSpec.shared_examples_for 'Msf::Module::DataStore' do
  it { is_expected.to respond_to :datastore }
  it { is_expected.to respond_to :import_defaults }
  it { is_expected.to respond_to :share_datastore }
end