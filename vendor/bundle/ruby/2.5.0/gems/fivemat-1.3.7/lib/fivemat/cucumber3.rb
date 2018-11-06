require 'cucumber/formatter/progress'

module Fivemat
  class Cucumber3 < ::Cucumber::Formatter::Progress
    include ElapsedTime

    def on_test_case_started(event)
      super
      feature = event.test_case.feature

      unless same_feature_as_previous_test_case?(feature)
        after_feature unless @current_feature.nil?
        before_feature(feature)
      end
    end

    def on_test_run_finished(_event)
      after_feature
      after_suite
    end

    private

    def before_feature(feature)
      @io.print "#{feature} "
      @io.flush
      @current_feature = feature
      @start_time = Time.now
    end

    def after_feature
      print_elapsed_time @io, @start_time
      @io.puts
      @io.flush

      print_elements(@pending_step_matches, :pending, 'steps')
      print_elements(@failed_results, :failed, 'steps')

      @pending_step_matches = []
      @failed_results = []
    end

    def after_suite
      @io.puts
      print_summary
    end

    def same_feature_as_previous_test_case?(feature)
      @current_feature && @current_feature.location == feature.location
    end
  end
end
