module FactoryBot
  # @api private
  class EvaluatorClassDefiner
    def initialize(attributes, parent_class)
      @parent_class = parent_class
      @attributes   = attributes

      attributes.each do |attribute|
        evaluator_class.define_attribute(attribute.name, &attribute.to_proc)
      end
    end

    def evaluator_class
      @evaluator_class ||= Class.new(@parent_class).tap do |klass|
        klass.attribute_lists ||= []
        klass.attribute_lists += [@attributes]
      end
    end
  end
end
