module FactoryBot
  # @api private
  class CallbacksObserver
    def initialize(callbacks, evaluator)
      @callbacks = callbacks
      @evaluator = evaluator
    end

    def update(name, result_instance)
      callbacks_by_name(name).each do |callback|
        callback.run(result_instance, @evaluator)
      end
    end

    private

    def callbacks_by_name(name)
      @callbacks.select { |callback| callback.name == name }
    end
  end
end
