require 'msf/core/modules'

# Monitor constants created by module loading to ensure that the loads in one example don't interfere with the
# assertions in another example.
module Metasploit::Framework::Spec::Constants
  # Regex parsing loaded module constants
  LOADED_MODULE_CHILD_CONSTANT_REGEXP = /^Mod(?<unpacked_full_name>[0-9a-f]+)$/
  # Path to log holding leaked constants from last spec run.
  LOG_PATHNAME = Pathname.new('log/leaked-constants.log')
  # The parent namespace constant that can have children added when loading modules.
  PARENT_CONSTANT = Msf::Modules

  # Configures after(:suite) callback for RSpec to check for leaked constants.
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.after(:suite) do
          count = 0

          LOG_PATHNAME.open('w') do |f|
            count = ::Metasploit::Framework::Spec::Constants.each { |child_name|
              f.puts child_name
            }
          end

          if count > 0
            $stderr.puts "#{count} #{'constant'.pluralize(count)} leaked under #{PARENT_CONSTANT}.  " \
                         "See #{LOG_PATHNAME} for details."
          else
            LOG_PATHNAME.delete
          end
        end
      end

      @configured = true
    end
  end

  # Adds action to `spec` task so that `rake spec` fails if `log/leaked-constants.log` exists after printing out the
  # leaked constants.
  #
  # @return [void]
  def self.define_task
    Rake::Task.define_task(:spec) do
      if LOG_PATHNAME.exist?
        $stderr.puts "Leaked constants detected under #{PARENT_CONSTANT}:"

        LOG_PATHNAME.open do |f|
          f.each_line do |line|
            constant = line.strip
            decoded = ''

            match = LOADED_MODULE_CHILD_CONSTANT_REGEXP.match(constant)

            if match
              potential_full_name = [match[:unpacked_full_name]].pack('H*')

              module_type, _reference_name = potential_full_name.split('/', 2)

              if Msf::MODULE_TYPES.include? module_type
                decoded = " # #{potential_full_name}"
              end
            end

            $stderr.puts "  #{constant}#{decoded}"
          end
        end

        exit 1
      end
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