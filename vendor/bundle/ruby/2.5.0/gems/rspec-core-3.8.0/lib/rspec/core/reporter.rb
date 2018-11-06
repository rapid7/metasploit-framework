module RSpec::Core
  # A reporter will send notifications to listeners, usually formatters for the
  # spec suite run.
  class Reporter
    # @private
    RSPEC_NOTIFICATIONS = Set.new(
      [
        :close, :deprecation, :deprecation_summary, :dump_failures, :dump_pending,
        :dump_profile, :dump_summary, :example_failed, :example_group_finished,
        :example_group_started, :example_passed, :example_pending, :example_started,
        :message, :seed, :start, :start_dump, :stop, :example_finished
      ])

    def initialize(configuration)
      @configuration = configuration
      @listeners = Hash.new { |h, k| h[k] = Set.new }
      @examples = []
      @failed_examples = []
      @pending_examples = []
      @duration = @start = @load_time = nil
      @non_example_exception_count = 0
      @setup_default = lambda {}
      @setup = false
      @profiler = nil
    end

    # @private
    attr_reader :examples, :failed_examples, :pending_examples

    # Registers a listener to a list of notifications. The reporter will send
    # notification of events to all registered listeners.
    #
    # @param listener [Object] An obect that wishes to be notified of reporter
    #   events
    # @param notifications [Array] Array of symbols represents the events a
    #   listener wishes to subscribe too
    def register_listener(listener, *notifications)
      notifications.each do |notification|
        @listeners[notification.to_sym] << listener
      end
      true
    end

    # @private
    def prepare_default(loader, output_stream, deprecation_stream)
      @setup_default = lambda do
        loader.setup_default output_stream, deprecation_stream
      end
    end

    # @private
    def registered_listeners(notification)
      @listeners[notification].to_a
    end

    # @overload report(count, &block)
    # @overload report(count, &block)
    # @param expected_example_count [Integer] the number of examples being run
    # @yield [Block] block yields itself for further reporting.
    #
    # Initializes the report run and yields itself for further reporting. The
    # block is required, so that the reporter can manage cleaning up after the
    # run.
    #
    # @example
    #
    #     reporter.report(group.examples.size) do |r|
    #       example_groups.map {|g| g.run(r) }
    #     end
    #
    def report(expected_example_count)
      start(expected_example_count)
      begin
        yield self
      ensure
        finish
      end
    end

    # @private
    def start(expected_example_count, time=RSpec::Core::Time.now)
      @start = time
      @load_time = (@start - @configuration.start_time).to_f
      notify :seed, Notifications::SeedNotification.new(@configuration.seed, seed_used?)
      notify :start, Notifications::StartNotification.new(expected_example_count, @load_time)
    end

    # @param message [#to_s] A message object to send to formatters
    #
    # Send a custom message to supporting formatters.
    def message(message)
      notify :message, Notifications::MessageNotification.new(message)
    end

    # @param event [Symbol] Name of the custom event to trigger on formatters
    # @param options [Hash] Hash of arguments to provide via `CustomNotification`
    #
    # Publish a custom event to supporting registered formatters.
    # @see RSpec::Core::Notifications::CustomNotification
    def publish(event, options={})
      if RSPEC_NOTIFICATIONS.include? event
        raise "RSpec::Core::Reporter#publish is intended for sending custom " \
              "events not internal RSpec ones, please rename your custom event."
      end
      notify event, Notifications::CustomNotification.for(options)
    end

    # @private
    def example_group_started(group)
      notify :example_group_started, Notifications::GroupNotification.new(group) unless group.descendant_filtered_examples.empty?
    end

    # @private
    def example_group_finished(group)
      notify :example_group_finished, Notifications::GroupNotification.new(group) unless group.descendant_filtered_examples.empty?
    end

    # @private
    def example_started(example)
      @examples << example
      notify :example_started, Notifications::ExampleNotification.for(example)
    end

    # @private
    def example_finished(example)
      notify :example_finished, Notifications::ExampleNotification.for(example)
    end

    # @private
    def example_passed(example)
      notify :example_passed, Notifications::ExampleNotification.for(example)
    end

    # @private
    def example_failed(example)
      @failed_examples << example
      notify :example_failed, Notifications::ExampleNotification.for(example)
    end

    # @private
    def example_pending(example)
      @pending_examples << example
      notify :example_pending, Notifications::ExampleNotification.for(example)
    end

    # @private
    def deprecation(hash)
      notify :deprecation, Notifications::DeprecationNotification.from_hash(hash)
    end

    # @private
    # Provides a way to notify of an exception that is not tied to any
    # particular example (such as an exception encountered in a :suite hook).
    # Exceptions will be formatted the same way they normally are.
    def notify_non_example_exception(exception, context_description)
      @configuration.world.non_example_failure = true
      @non_example_exception_count += 1

      example = Example.new(AnonymousExampleGroup, context_description, {})
      presenter = Formatters::ExceptionPresenter.new(exception, example, :indentation => 0)
      message presenter.fully_formatted(nil)
    end

    # @private
    def finish
      close_after do
        stop
        notify :start_dump,    Notifications::NullNotification
        notify :dump_pending,  Notifications::ExamplesNotification.new(self)
        notify :dump_failures, Notifications::ExamplesNotification.new(self)
        notify :deprecation_summary, Notifications::NullNotification
        unless mute_profile_output?
          notify :dump_profile, Notifications::ProfileNotification.new(@duration, @examples,
                                                                       @configuration.profile_examples,
                                                                       @profiler.example_groups)
        end
        notify :dump_summary, Notifications::SummaryNotification.new(@duration, @examples, @failed_examples,
                                                                     @pending_examples, @load_time,
                                                                     @non_example_exception_count)
        notify :seed, Notifications::SeedNotification.new(@configuration.seed, seed_used?)
      end
    end

    # @private
    def close_after
      yield
    ensure
      close
    end

    # @private
    def stop
      @duration = (RSpec::Core::Time.now - @start).to_f if @start
      notify :stop, Notifications::ExamplesNotification.new(self)
    end

    # @private
    def notify(event, notification)
      ensure_listeners_ready
      registered_listeners(event).each do |formatter|
        formatter.__send__(event, notification)
      end
    end

    # @private
    def abort_with(msg, exit_status)
      message(msg)
      close
      exit!(exit_status)
    end

    # @private
    def fail_fast_limit_met?
      return false unless (fail_fast = @configuration.fail_fast)

      if fail_fast == true
        @failed_examples.any?
      else
        fail_fast <= @failed_examples.size
      end
    end

  private

    def ensure_listeners_ready
      return if @setup

      @setup_default.call
      @profiler = Profiler.new
      register_listener @profiler, *Profiler::NOTIFICATIONS
      @setup = true
    end

    def close
      notify :close, Notifications::NullNotification
    end

    def mute_profile_output?
      # Don't print out profiled info if there are failures and `--fail-fast` is
      # used, it just clutters the output.
      !@configuration.profile_examples? || fail_fast_limit_met?
    end

    def seed_used?
      @configuration.seed && @configuration.seed_used?
    end
  end

  # @private
  # # Used in place of a {Reporter} for situations where we don't want reporting output.
  class NullReporter
    def self.method_missing(*)
      # ignore
    end
    private_class_method :method_missing
  end
end
