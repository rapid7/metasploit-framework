module Metasploit::Framework::Spec::Metasploit::Model::Spec
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.before(:suite) do
          ::Metasploit::Model::Spec.temporary_pathname = ::Metasploit::Framework.root.join('spec', 'tmp')
          # Clean up any left over files from a previously aborted suite
          ::Metasploit::Model::Spec.remove_temporary_pathname
        end

        config.after(:each) do
          ::Metasploit::Model::Spec.remove_temporary_pathname
        end
      end

      @configured = true
    end

    @configured
  end
end