# Use in a context to clean up the constants that are created by the module loader.
RSpec.shared_context 'Metasploit::Framework::Spec::Constants cleaner' do
  after(:example) do
    Metasploit::Framework::Spec::Constants.clean
  end
end