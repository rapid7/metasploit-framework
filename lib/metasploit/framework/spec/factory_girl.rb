module Metasploit::Framework::Spec::FactoryGirl
  def self.configure!
    unless @configured
      # Metasploit::Model::Spec.temporary_pathname needs to be set before factory are defined
      ::Metasploit::Framework::Spec::Metasploit::Model::Spec.configure!

      RSpec.configure do |config|
        config.before(:suite) do
          ::FactoryGirl.definition_file_paths = Metasploit::Framework::Spec::ROOTED_MODULES.collect { |rooted|
            rooted.root.join('spec', 'factories')
          }

          ::FactoryGirl.find_definitions
        end
      end

      @configured = true
    end
  end
end