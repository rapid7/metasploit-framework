# @note Requires use of 'untested payloads' shared context for tracking of `@actual_ancestor_reference_name_set`.
#
# Tests that the `:ancestor_reference_names` can be loaded from `:modules_pathname` and once the ancestors are loaded
# that `:reference_name` can be instantiated.
#
# # Payload Reference Name Derivation
# You can see this naming logic [here](https://github.com/rapid7/metasploit-framework/blob/1508be6254f698f345616d14415bce164bf377f9/lib/msf/core/payload_set.rb#L132-L148).
#
# ## Single
# 1. Remove the payload type prefix, `modules/payloads/singles`, from the path.
# 2. Remove the file extension, `.rb` from the path
#
# This is <reference_name>
#
# ## Staged
#
# ### Stager
# Determine if the stager module has a `handler_type_alias`
# No) Use stager's handler's `handler_type` as `<handler_type>`.
# Yes) Use the return value from `handler_type_alias` as `<handler_type>`.
#
# ### Stage
# 1. Remove the payload type prefix, `modules/payloads/stages`, from the path.
# 2. Remove the file extension, `.rb` from the path.
#
# This is <stage_reference_name>.
#
# ### Combining
# The final staged module's combined `<reference_name>` is `<stage_reference_name>/<handler_type>`.
#
# @example Using 'payload can be instantiated' with `Metasploit::Framework::Spec::UntestedPayloads.define_task` and 'untested payloads' shared context
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
# @param options [Hash{Symbol => Array<String>, Pathname, String}]
# @option options [Array<String>] :ancestor_reference_names The reference names of the payload modules that are included
#   in {Msf::Payload} to make the `:reference_name` payload.  Ancestor reference names are the names of the files under
#   `modules/payloads` without the extension `.rb` that are mixed together to form a payload module `Class`.  For
#   single payloads, there will be one ancestor reference name from `modules/payloads/singles`, while for staged
#   payloads there with be one ancestor reference name from `modules/payloads/stagers` and one ancestor reference name
#   from `modules/payloads/stages`.
# @option options [Pathname] :modules_pathname The `modules` directory from which to load `:ancestor_reference_names`.
# @option options [String] :reference_name The reference name for payload class that should be instantiated from mixing
#   `:ancestor_reference_names`.
# @return [void]
shared_examples_for 'payload can be instantiated' do |options|
  options.assert_valid_keys(:ancestor_reference_names, :modules_pathname, :reference_name)

  ancestor_reference_names = options.fetch(:ancestor_reference_names)

  modules_pathname = options.fetch(:modules_pathname)
  modules_path = modules_pathname.to_path

  reference_name = options.fetch(:reference_name)

  module_type = 'payload'

  include_context 'Msf::Simple::Framework'

  #
  # lets
  #

  let(:loader) {
    loader = framework.modules.send(:loaders).find { |loader|
      loader.loadable?(modules_path)
    }

    # Override load_error so that rspec will print it instead of going to framework log
    def loader.load_error(module_path, error)
      raise error
    end

    loader
  }

  let(:module_set) {
    framework.modules.module_set(module_type)
  }

  context reference_name  do
    ancestor_reference_names.each do |ancestor_reference_name|
      it "can load '#{module_type}/#{ancestor_reference_name}'" do
        @actual_ancestor_reference_name_set.add(ancestor_reference_name)

        loaded = loader.load_module(modules_path, module_type, ancestor_reference_name)

        expect(loaded).to eq(true), "#{ancestor_reference_name} failed to load from #{modules_path}"
      end
    end

    it 'can be instantiated' do
      ancestor_reference_names.each do |ancestor_reference_name|
        loaded = loader.load_module(modules_path, module_type, ancestor_reference_name)

        expect(loaded).to eq(true), "#{ancestor_reference_name} failed to load from #{modules_path}"
      end

      module_instance = nil

      expect {
        module_instance = module_set.create(reference_name)
      }.not_to raise_error

      expect(module_instance).not_to be_nil, "Could not instantiate #{module_type}/#{reference_name}"
    end
  end
end
