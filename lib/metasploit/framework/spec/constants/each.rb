# @note This should only temporarily be used in `spec/spec_helper.rb` when
#   `Metasploit::Framework::Spec::Constants::Suite.configure!` detects a leak.  Permanently having
#   `Metasploit::Framework::Spec::Constants::Each.configure!` can lead to false positives when modules are purposely
#   loaded in a `before(:all)` and cleaned up in a `after(:all)`.
#
# Fails example if it leaks module loading constants.
module Metasploit::Framework::Spec::Constants::Each
  #
  # CONSTANTS
  #

  LOG_PATHNAME = Pathname.new('log/metasploit/framework/spec/constants/each.log')

  #
  # Module Methods
  #

  class << self
    attr_accessor :leaks_cleaned
  end

  # Is Metasploit::Framework::Spec::Constants::Each.configure! still necessary or should it be removed?
  #
  # @return [true] if {configure!}'s `before(:each)` cleaned up leaked constants
  # @return [false] otherwise
  def self.leaks_cleaned?
    !!@leaks_cleaned
  end

  # Configures after(:each) callback for RSpe to fail example if leaked constants.
  #
  # @return [void]
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.before(:each) do |example|
          leaks_cleaned = Metasploit::Framework::Spec::Constants.clean

          if leaks_cleaned
            $stderr.puts "Cleaned leaked constants before #{example.metadata.full_description}"
          end

          # clean so that leaks from earlier example aren't attributed to this example
          Metasploit::Framework::Spec::Constants::Each.leaks_cleaned ||= leaks_cleaned
        end

        config.after(:each) do |example|
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

        config.after(:suite) do
          if Metasploit::Framework::Spec::Constants::Each.leaks_cleaned?
            if LOG_PATHNAME.exist?
              LOG_PATHNAME.delete
            end
          else
            LOG_PATHNAME.open('w') { |f|
              f.puts "No leaks were cleaned by `Metasploit::Framework::Spec::Constants::Each.configured!`.  Remove " \
                     "it from `spec/spec_helper.rb` so it does not interfere with contexts that persist loaded " \
                     "modules for entire context and clean up modules in `after(:all)`"
            }
          end
        end
      end

      @configured = true
    end
  end

  # Whether {configure!} was called
  #
  # @return [Boolean]
  def self.configured?
    !!@configured
  end

  # Adds action to `spec` task so that `rake spec` fails if configured! is unnecessary in `spec/spec_helper.rb` and
  # should be removed
  #
  # @return [void]
  def self.define_task
    Rake::Task.define_task('metasploit:framework:spec:constant:each:clean') do
      if LOG_PATHNAME.exist?
        LOG_PATHNAME.delete
      end
    end

    Rake::Task.define_task(spec: 'metasploit:framework:spec:constant:each:clean')

    Rake::Task.define_task(:spec) do
      if LOG_PATHNAME.exist?
        LOG_PATHNAME.open { |f|
          f.each_line do |line|
            $stderr.write line
          end
        }

        exit(1)
      end
    end
  end
end
