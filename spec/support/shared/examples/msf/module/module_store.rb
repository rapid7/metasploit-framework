RSpec.shared_examples_for 'Msf::Module::ModuleStore' do
  it { is_expected.to respond_to :[] }
  it { is_expected.to respond_to :[]= }
  it { is_expected.to respond_to :module_store }
  it { is_expected.to respond_to :module_store= }
end