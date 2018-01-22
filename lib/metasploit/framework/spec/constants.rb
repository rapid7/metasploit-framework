require 'msf/core/modules'

# Monitor constants created by module loading to ensure that the loads in one example don't interfere with the
# assertions in another example.
module Metasploit::Framework::Spec::Constants
  extend ActiveSupport::Autoload

  autoload :Each
  autoload :Suite

  #
  # CONSTANTS
  #

  # Regex parsing loaded module constants
  LOADED_MODULE_CHILD_CONSTANT_REGEXP = /^Mod(?<unpacked_full_name>[0-9a-f]+)$/
  # The parent namespace child_constant_name that can have children added when loading modules.
  PARENT_CONSTANT = Msf::Modules
  # Constant names under {PARENT_CONSTANT} that can persist between specs because they are part of the loader library
  # and not dynamically loaded code
  PERSISTENT_CHILD_CONSTANT_NAMES = %w{
    Error
    External
    Loader
    Metadata
    MetasploitClassCompatibilityError
    Namespace
    VersionCompatibilityError
  }.map(&:to_sym)

  # Cleans child constants from {PARENT_CONSTANT}.
  #
  # @return [true] if there were leaked constants that were cleaned.
  # @return [false] if there were no leaked constants.
  # @see each
  def self.clean
    count = each do |child_name|
      PARENT_CONSTANT.send(:remove_const, child_name)
    end

    count != 0
  end

  # Adds actions to `spec` task so that `rake spec` fails if any of the following:
  #
  # # `log/leaked-constants.log` exists after printing out the leaked constants.
  # # Each.configured! is unnecessary in `spec/spec_helper.rb` and should be removed.
  #
  # @return [void]
  def self.define_task
    Suite.define_task
    # After Suite as Suite will kill for leaks before Each say it cleaned no leaks in case there are leaks in an
    # `after(:all)` that {Each} won't catch in its `after(:each)` checks.
    Each.define_task
  end

  # Yields each child_constant_name under {PARENT_CONSTANT}.
  #
  # @yield [child_name]
  # @yieldparam child_name [Symbol] name of child_constant_name relative to {PARENT_CONSTANT}.
  # @yieldreturn [void]
  # @return [Integer] count
  def self.each
    inherit = false
    count = 0

    child_constant_names = PARENT_CONSTANT.constants(inherit)

    child_constant_names.each do |child_constant_name|
      unless PERSISTENT_CHILD_CONSTANT_NAMES.include? child_constant_name
        count += 1
        yield child_constant_name
      end
    end

    count
  end

  # The module full name for `child_constant_name`
  #
  # @param child_constant_name [String] the name of a child constant_name under {PARENT_CONSTANT}.
  # @return [String] full module name used to load `child_constant_name`.
  # @return [nil] if `child_constant_name` does not correspond to a loaded module.
  def self.full_name(child_constant_name)
    full_name = nil

    match = LOADED_MODULE_CHILD_CONSTANT_REGEXP.match(child_constant_name)

    if match
      potential_full_name = [match[:unpacked_full_name]].pack('H*')

      module_type, _reference_name = potential_full_name.split('/', 2)

      if Msf::MODULE_TYPES.include? module_type
        full_name = potential_full_name
      end
    end

    full_name
  end
end
