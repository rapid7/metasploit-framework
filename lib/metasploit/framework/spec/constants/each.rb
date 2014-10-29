# @note This should only temporarily be used in `spec/spec_helper.rb` when
#   `Metasploit::Framework::Spec::Constants::Suite.configure!` detects a leak.  Permanently having
#   `Metasploit::Framework::Spec::Constants::Each.configure!` can lead to false positives when modules are purposely
#   loaded in a `before(:all)` and cleaned up in a `after(:all)`.
#
# Fails example if it leaks module loading constants.
module Metasploit::Framework::Spec::Constants::Each
  # Configures after(:each) callback for RSpe to fail example if leaked constants.
  #
  # @return [void]
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.before(:each) do
          # clean so that leaks from earlier example aren't attributed to this example
          Metasploit::Framework::Spec::Constants.clean
        end

        config.after(:each) do
          child_names = Metasploit::Framework::Spec::Constants.to_enum(:each).to_a

          if child_names.length > 0
            lines = ['Leaked constants:']

            child_names.sort.each do |child_name|
              lines << "  #{child_name}"
            end

            lines << ''
            lines << "Add `include_context 'Metasploit::Framework::Spec::Constants cleaner'` to clean up constants from #{example.metadata.full_description}"

            message = lines.join("\n")

            # use caller metadata so that Jump to Source in the Rubymine RSpec running jumps to the example instead of
            # here
            fail RuntimeError, message, example.metadata[:caller]
          end
        end
      end

      @configured = true
    end
  end
end