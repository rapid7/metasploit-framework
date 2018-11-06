module FactoryBot
  # @api private
  class NullFactory
    attr_reader :definition

    def initialize
      @definition = Definition.new(:null_factory)
    end

    delegate :defined_traits, :callbacks, :attributes, :constructor,
      :to_create, to: :definition

    def compile; end
    def class_name; end
    def evaluator_class; FactoryBot::Evaluator; end
    def hierarchy_class; FactoryBot::DefinitionHierarchy; end
  end
end
