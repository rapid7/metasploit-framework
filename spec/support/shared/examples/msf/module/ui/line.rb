RSpec.shared_examples_for 'Msf::Module::UI::Line' do
  it_should_behave_like 'Msf::Module::UI::Line::Verbose'

  it { is_expected.to respond_to :print_line }
  it { is_expected.to respond_to :print_line_prefix }
end