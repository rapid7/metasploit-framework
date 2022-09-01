RSpec.shared_examples_for 'Msf::Module::UI::Message' do
  it_should_behave_like 'Msf::Module::UI::Message::Verbose'

  it { is_expected.to respond_to :print_error }
  it { is_expected.to respond_to :print_bad }
  it { is_expected.to respond_to :print_good }
  it { is_expected.to respond_to :print_prefix }
  it { is_expected.to respond_to :print_status }
  it { is_expected.to respond_to :print_warning }
end
