require 'msf/core/modules'

# Monitor constants created by module loading to ensure that the loads in one example don't interfere with the
# assertions in another example.
module Metasploit::Framework::Spec::Constants::Suite
  #
  # CONSTANTS
  #

  # Path to log holding leaked constants from last spec run.
  LOG_PATHNAME = Pathname.new('log/leaked-constants.log')

  # Configures after(:suite) callback for RSpec to check for leaked constants.
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.after(:suite) do
          count = 0

          LOG_PATHNAME.open('w') do |f|
            count = Metasploit::Framework::Spec::Constants.each { |child_name|
              f.puts child_name
            }
          end

          if count > 0
            $stderr.puts "#{count} #{'constant'.pluralize(count)} leaked under "  \
                         "#{Metasploit::Framework::Spec::Constants::PARENT_CONSTANT}. See #{LOG_PATHNAME} for details."
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
        $stderr.puts "Leaked constants detected under #{Metasploit::Framework::Spec::Constants::PARENT_CONSTANT}:"

        LOG_PATHNAME.open do |f|
          f.each_line do |line|
            constant_name = line.strip
            full_name = Metasploit::Framework::Spec::Constants.full_name(constant_name)

            if full_name
              formatted_full_name = " # #{full_name}"
            end

            $stderr.puts "  #{constant_name}#{formatted_full_name}"
          end
        end

        exit 1
      end
    end
  end
end