require 'msf/core/modules'

# Monitor constants created by module loading to ensure that the loads in one example don't interfere with the
# assertions in another example.
module Metasploit::Framework::Spec::Constants
  # The parent namespace constant that can have children added when loading modules.
  PARENT_CONSTANT = Msf::Modules

  # Configures after(:suite) callback for RSpec to check for leaked constants.
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.after(:suite) do
          ::Metasploit::Framework::Spec::Constants.each { |child_name|
            $stderr.puts "#{child_name} not removed from #{PARENT_CONSTANT}"
          }
        end
      end

      @configured = true
    end
  end

  # Yields each constant under {PARENT_CONSTANT}.
  #
  # @yield [child_name]
  # @yieldparam child_name [String] name of constant relative to {PARENT_CONSTANT}.
  # @yieldreturn [void]
  # @return [Integer] count
  def self.each
    inherit = false
    count = 0

    child_constant_names = PARENT_CONSTANT.constants(inherit)

    child_constant_names.each do |child_constant_name|
      count += 1
      yield child_constant_name
    end

    count
  end
end