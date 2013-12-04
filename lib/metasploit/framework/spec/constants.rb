require 'msf/core/modules'
require 'msf/core/payloads'

# Monitor constants created by ancestor and class loading to ensure that the loads in one example don't interfere with
# the assertions in another example.
module Metasploit::Framework::Spec::Constants
  # The parent namespace constants that can have children added when loading ancestors or classes.
  PARENTS = [
      Msf::Modules,
      Msf::Payloads
  ]

  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.after(:suite) do
          count = ::Metasploit::Framework::Spec::Constants.each { |parent_constant, child_name|
            $stderr.puts "#{child_name} not removed from #{parent_constant}"
          }

          if count > 0
            $stderr.puts "Use `include_context 'Metasploit::Framework::Spec::Constants tracker'` to determine which examples are leaking constants"
          end
        end
      end

      @configured = true
    end
  end

  # Yields each constant under {PARENTS}.
  #
  # @yield [parent, child_name]
  # @yieldparam parent [Module] parent constant
  # @yieldparam child_name [String] name of constant relative to `parent`.
  # @yieldreturn [void]
  # @return [Integer] count
  def self.each
    inherit = false
    count = 0

    PARENTS.each do |parent|
      child_constant_names = parent.constants(inherit)

      child_constant_names.each do |child_constant_name|
        count += 1
        yield parent, child_constant_name
      end
    end

    count
  end
end