RSpec.shared_examples_for 'Msf::Module::UUID' do
  it { is_expected.to respond_to :uuid }
end
