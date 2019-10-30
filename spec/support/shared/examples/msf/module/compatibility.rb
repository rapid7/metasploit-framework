RSpec.shared_examples_for 'Msf::Module::Compatibility' do
  it { is_expected.to respond_to :compat }
  it { is_expected.to respond_to :compatible? }
  it { is_expected.to respond_to_protected :init_compat }
end
