module FactoryBot
  module Strategy
    class Create
      def association(runner)
        runner.run
      end

      def result(evaluation)
        evaluation.object.tap do |instance|
          evaluation.notify(:after_build, instance)
          evaluation.notify(:before_create, instance)
          evaluation.create(instance)
          evaluation.notify(:after_create, instance)
        end
      end
    end
  end
end
