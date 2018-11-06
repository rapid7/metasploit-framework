module FactoryBot
  module Strategy
    class AttributesFor
      def association(runner)
        runner.run(:null)
      end

      def result(evaluation)
        evaluation.hash
      end
    end
  end
end
