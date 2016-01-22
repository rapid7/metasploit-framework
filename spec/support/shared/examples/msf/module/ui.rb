RSpec.shared_examples_for 'Msf::Module::UI' do
  it_should_behave_like 'Msf::Module::UI::Line'
  it_should_behave_like 'Msf::Module::UI::Message'
end