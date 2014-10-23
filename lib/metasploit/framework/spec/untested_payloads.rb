# @note needs to use explicit nesting. so this file can be loaded directly without loading 'metasploit/framework' which
#   allows for faster loading of rake tasks
module Metasploit
  module Framework
    module Spec
      module UntestedPayloads
        # @note `Metasploit::Framework::Spec::UntestedPayloads.define_task` should be run after the normal spec task is
        #   defined.
        #
        # Adds action to `spec` tasks so that `rake spec` fails if  `log/untested-payloads.log` exists and prints out untested
        # payloads from that log to stderr.
        #
        # @return [void]
        def self.define_task
          Rake::Task.define_task :spec do
            untested_payloads_pathname = Pathname.new 'log/untested-payloads.log'

            if untested_payloads_pathname.exist?
              $stderr.puts "Untested payload detected.  Add tests to spec/modules/payload_spec.rb for payloads classes composed of the following payload modules:"

              untested_payloads_pathname.open do |f|
                f.each_line do |line|
                  $stderr.write "  #{line}"
                end
              end

              exit 1
            end
          end
        end
      end
    end
  end
end