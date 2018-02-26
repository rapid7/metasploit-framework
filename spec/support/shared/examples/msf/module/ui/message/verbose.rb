RSpec.shared_examples_for 'Msf::Module::UI::Message::Verbose' do
  it { is_expected.to respond_to :vprint_error }
  it { is_expected.to respond_to :vprint_bad }
  it { is_expected.to respond_to :vprint_good }
  it { is_expected.to respond_to :vprint_status }
  it { is_expected.to respond_to :vprint_warning }
end
