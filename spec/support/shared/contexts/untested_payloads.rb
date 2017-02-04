# Use along with `it_should_behave_like 'payload can be instantiated'` to detect if a payload under `:modules_pathname`
# was not tested.  If any payloads are untested, an error will be written to stderr and the names of untested payloads
# will be logged to `log/untested-payloads.log`.  This log is reset for run of context, so if there were previously
# untested payloads and there aren't anymore, then `log/untested-payloads.log` will be deleted.  Can be used with
# {Metasploit::Framework::Spec::UntestedPayloads.define_task} so that the `spec` task fails if there are untested
# payloads.
#
# @example Using 'untested payloads' with `Metasploit::Framework::Spec::UntestedPayloads.define_task` and 'payloads can be instantiated' shared examples
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
#                                'stagers/my/payload/handler',
#                                modules_pathname: modules_pathname,
#                                reference_name: 'my/staged/payload/handler'
#                              ]
#      end
#   end
#
# @param options [Hash{Symbol => Pathname}]
# @option options [Pathname] :modules_pathname Pathname of `modules` directory underwhich payloads are defined on the
#   file system.
RSpec.shared_context 'untested payloads' do |options={}|
  options.assert_valid_keys(:modules_pathname)

  modules_pathname = options.fetch(:modules_pathname)

  before(:context) do
    @expected_ancestor_reference_name_set = Set.new
    @actual_ancestor_reference_name_set = Set.new

    payloads_pathname = modules_pathname.join('payloads')

    Dir.glob(payloads_pathname.join('**', '*.rb')) do |expected_ancestor_path|
      expected_ancestor_pathname = Pathname.new(expected_ancestor_path)
      expected_ancestor_reference_pathname = expected_ancestor_pathname.relative_path_from(payloads_pathname)
      expected_ancestor_reference_name = expected_ancestor_reference_pathname.to_path.gsub(/.rb$/, '')

      @expected_ancestor_reference_name_set.add(expected_ancestor_reference_name)
    end
  end

  after(:context) do
    missing_ancestor_reference_name_set = @expected_ancestor_reference_name_set - @actual_ancestor_reference_name_set

    untested_payloads_pathname = Pathname.new('log/untested-payloads.log')

    if missing_ancestor_reference_name_set.empty?
      if untested_payloads_pathname.exist?
        untested_payloads_pathname.delete
      end
    else
      untested_payloads_pathname.open('w') do |f|
        missing_ancestor_reference_name_set.sort.each do |missing_ancestor_reference_name|
          f.puts missing_ancestor_reference_name
        end
      end

      $stderr.puts "Some payloads are untested.  See log/untested-payload.log for details."
    end
  end
end