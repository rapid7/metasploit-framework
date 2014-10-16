shared_examples_for 'Msf::Module::Options' do
  it { is_expected.to respond_to :deregister_options }
  it { is_expected.to respond_to :options }
  it { is_expected.to respond_to :validate }
  it { is_expected.to respond_to :register_advanced_options }
  it { is_expected.to respond_to :register_evasion_options }
  it { is_expected.to respond_to :register_options }
end