require 'observer'

module FactoryBot
  class Evaluation
    include Observable

    def initialize(evaluator, attribute_assigner, to_create)
      @evaluator = evaluator
      @attribute_assigner = attribute_assigner
      @to_create = to_create
    end

    delegate :object, :hash, to: :@attribute_assigner

    def create(result_instance)
      case @to_create.arity
      when 2 then @to_create[result_instance, @evaluator]
      else @to_create[result_instance]
      end
    end

    def notify(name, result_instance)
      changed
      notify_observers(name, result_instance)
    end
  end
end
