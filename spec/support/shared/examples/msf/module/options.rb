RSpec.shared_examples_for 'Msf::Module::Options' do
  it { is_expected.to respond_to_protected :deregister_options }
  it { is_expected.to respond_to :options }
  it { is_expected.to respond_to :validate }
  it { is_expected.to respond_to_protected :register_advanced_options }
  it { is_expected.to respond_to_protected :register_evasion_options }
  it { is_expected.to respond_to_protected :register_options }
end