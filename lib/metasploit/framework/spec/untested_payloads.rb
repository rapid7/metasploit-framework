# @note needs to use explicit nesting. so this file can be loaded directly without loading 'metasploit/framework' which
#   allows for faster loading of rake tasks.
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
        # # @example Using `Metasploit::Framework::Spec::UntestedPayloads.define_task` with 'payload can be instantiated' shared examples  and 'untested payloads' shared context
        #   # Rakefile
        #   require 'metasploit/framework/spec/untested_payloads'
        #
        #   # defined spec task with rspec-rails
        #   My::Application.load_tasks
        #   # extends spec task to fail when there are untested payloads
        #   Metasploit::Framework::Spec::UntestedPayloads.define_task
        #
        #   # spec/modules/payloads_spec.rb
        #   require 'spec_helper'
        #
        #   describe 'modules/payloads' do
        #      modules_pathname = Pathname.new(__FILE__).parent.parent.parent.join('modules')
        #
        #      include_context 'untested payloads', modules_pathname: modules_pathname
        #
        #      context 'my/staged/payload/handler' do
        #        it_should_behave_like 'payload can be instantiated',
        #                              ancestor_reference_names: [
        #                                'stages/my/payload',
        #                                'stagers/my/payload/handler'
        #                              ],
        #                              modules_pathname: modules_pathname,
        #                              reference_name: 'my/staged/payload/handler'
        #      end
        #   end
        #
        # @return [void]
        def self.define_task
          Rake::Task.define_task :spec do
            untested_payloads_pathname = Pathname.new 'log/untested-payloads.log'

            if untested_payloads_pathname.exist?
              tool_path = 'tools/modules/missing_payload_tests.rb'

              $stderr.puts "Untested payload detected.  Running `#{tool_path}` to see contexts to add to " \
                           "`spec/modules/payloads_spec.rb` to test those payload ancestor reference names."

              system(tool_path)

              exit 1
            end
          end
        end
      end
    end
  end
end
