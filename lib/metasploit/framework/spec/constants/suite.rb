# Logs if constants created by module loading are left over after suite has completed.
module Metasploit::Framework::Spec::Constants::Suite
  #
  # CONSTANTS
  #

  LOGS_PATHNAME = Pathname.new('log/metasploit/framework/spec/constants/suite')

  # Logs leaked constants to LOG_PATHNAME and prints `message` to stderr.
  #
  # @param hook (see log_pathname)
  # @param message [String] additional message printed to stderr when there is at least one leaked constant.
  # @return [void]
  def self.log_leaked_constants(hook, message)
    count = 0
    hook_log_pathname = log_pathname(hook)
    hook_log_pathname.parent.mkpath

    hook_log_pathname.open('w') do |f|
      count = Metasploit::Framework::Spec::Constants.each do |child_name|
        f.puts child_name
      end
    end

    if count > 0
      $stderr.puts "#{count} #{'constant'.pluralize(count)} leaked under " \
                   "#{Metasploit::Framework::Spec::Constants::PARENT_CONSTANT}. #{message} See #{hook_log_pathname} " \
                   "for details."
    else
      hook_log_pathname.delete
    end
  end

  # Configures after(:suite) callback for RSpec to check for leaked constants.
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.before(:suite) do
          Metasploit::Framework::Spec::Constants::Suite.log_leaked_constants(
              :before,
              'Modules are being loaded outside callbacks before suite starts.'
          )
        end

        config.after(:suite) do
          Metasploit::Framework::Spec::Constants::Suite.log_leaked_constants(
              :after,
              'Modules are being loaded inside callbacks or examples during suite run.'
          )
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
      leaked_before = Metasploit::Framework::Spec::Constants::Suite.print_leaked_constants(:before)
      leaked_after = Metasploit::Framework::Spec::Constants::Suite.print_leaked_constants(:after)

      # leaks after suite can be be cleaned up by {Metasploit::Framework::Spec::Constants::Each.configure!}, but
      # leaks before suite require user intervention to find the leaks since it's a programming error in how the specs
      # are written where Modules are being loaded in the context scope.
      if leaked_after
        $stderr.puts
        $stderr.puts "Add `Metasploit::Framework::Spec::Constants::Each.configure!` to `spec/spec_helper.rb` " \
                     "**NOTE: `Metasploit::Framework::Spec::Constants::Each` may report false leaks if `after(:all)` " \
                     "is used to clean up constants instead of `after(:each)`**"
      end

      if leaked_before || leaked_after
        exit 1
      end
    end
  end

  # @param hook [:after, :before] Whether the log is recording leaked constants `:before` the suite runs or `:after` the
  #   suite runs.
  def self.log_pathname(hook)
    LOGS_PATHNAME.join("#{hook}.log")
  end

  # Prints logged leaked constants to stderr.
  #
  # @param hook [:after, :before] Whether the log is recording leaked constants `:before` the suite runs or `:after` the
  #   suite runs.
  # @return [true] if leaks printed
  # @return [false] otherwise
  def self.print_leaked_constants(hook)
    hook_log_pathname = log_pathname(hook)

    leaks = false

    if hook_log_pathname.exist?
      leaks = true
      $stderr.puts "Leaked constants detected under #{Metasploit::Framework::Spec::Constants::PARENT_CONSTANT} #{hook} suite:"

      hook_log_pathname.open do |f|
        f.each_line do |line|
          constant_name = line.strip
          full_name = Metasploit::Framework::Spec::Constants.full_name(constant_name)

          if full_name
            formatted_full_name = " # #{full_name}"
          end

          $stderr.puts "  #{constant_name}#{formatted_full_name}"
        end
      end
    end

    leaks
  end
end
