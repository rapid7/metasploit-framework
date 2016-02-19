RSpec.shared_examples_for 'Msf::Module::Arch' do
  it { is_expected.to respond_to :arch }
  it { is_expected.to respond_to :arch? }
  it { is_expected.to respond_to :arch_to_s }
  it { is_expected.to respond_to :each_arch }
end