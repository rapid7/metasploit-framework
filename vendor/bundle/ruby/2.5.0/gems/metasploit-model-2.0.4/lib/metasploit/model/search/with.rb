# Generalizes {Metasploit::Model::Search::Attribute operators from attributes} to anything directly registered as
# an operator on a class.
#
# {include:Metasploit::Model::Search::Operator}
#
# # Testing
#
# {ClassMethods#search_with} calls can be tested with the 'search_with' shared example.  First, ensure
# the shared examples from `metasploit-model` are required in your `spec_helper.rb`:
#
#     # spec/spec_helper.rb
#     support_glob = Metasploit::Model::Engine.root.join('spec', 'support', '**', '*.rb')
#
#     Dir.glob(support_glob) do |path|
#       require path
#     end
#
# In the spec fo the `Class` that called `search_with`, use the 'search_with' shared example by passing the
# arguments passed to {ClassMethods#search_attribute}.
#
#     # app/models/my_class.rb
#     class MyClass
#       include Metasploit::Model::Search
#
#       #
#       # Search
#       #
#
#       search_with MyOperatorClass,
#                   foo: :bar
#     end
#
#     # spec/app/models/my_class_spec.rb
#     require 'spec_helper'
#
#     describe MyClass do
#       context 'search' do
#         context 'attributes' do
#           it_should_behave_like 'search_with',
#                                 MyOperatorClass,
#                                 foo: :bar
#         end
#       end
#     end
module Metasploit::Model::Search::With
  extend ActiveSupport::Concern

  # Defines `search_with` DSL, which is a lower-level way than search_attribute to add operators.  `search_with`
  # allows instance of arbitrary operator_classes to be registered in {#search_with_operator_by_name}.
  module ClassMethods
    # Declares that this class should be search with an instance of the given `operator_class`.
    #
    # @param operator_class [Class<Metasploit::Model::Search::Operator::Base>] a class to initialize.
    # @param options [Hash] Options passed to `operator_class.new` along with `{:klass => self}`, so that the
    #   `operator_class` instance knows it was registered as search this class.
    # @return [Metasploit::Model::Search::Operator::Base]
    # @raise (see Metasploit::Model::Base#invalid!)
    def search_with(operator_class, options={})
      merged_operations = options.merge(
          :klass => self
      )
      operator = operator_class.new(merged_operations)
      operator.valid!

      search_with_operator_by_name[operator.name] = operator
    end

    # Operators registered with {#search_with}.
    #
    # @return [Hash{Symbol => Metasploit::Model::Search::Operator::Base}] Maps
    #   {Metasploit::Model::Search::Operator::Base#name} keys to {Metasploit::Model::Search::Operator::Base#name}
    #   values.
    def search_with_operator_by_name
      @search_with_operator_by_name ||= {}
    end
  end
end
