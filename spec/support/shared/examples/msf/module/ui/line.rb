shared_examples_for 'Msf::Module::UI::Line' do
  it { is_expected.to respond_to :print_line }
  it { is_expected.to respond_to :print_line_prefix }
end