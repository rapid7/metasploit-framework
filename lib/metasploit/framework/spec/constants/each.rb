# Fails example if it leaks module loading constants.
module Metasploit::Framework::Spec::Constants::Each
  # Configures after(:each) callback for RSpe to fail example if leaked constants.
  #
  # @return [void]
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.after(:each) do
          child_names = Metasploit::Framework::Spec::Constants.to_enum(:each).to_a

          if child_names.length > 0
            lines = ['Leaked constants:']

            child_names.sort.each do |child_name|
              lines << "  #{child_name}"
            end

            message = lines.join("\n")

            # clean so that leaks from one example aren't attributed to later examples
            Metasploit::Framework::Spec::Constants.clean

            fail message
          end
        end
      end

      @configured = true
    end
  end
end