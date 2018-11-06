require "active_job/base"
require "active_job/arguments"

module RSpec
  module Rails
    module Matchers
      # Namespace for various implementations of ActiveJob features
      #
      # @api private
      module ActiveJob
        # rubocop: disable Style/ClassLength
        # @private
        class Base < RSpec::Matchers::BuiltIn::BaseMatcher
          def initialize
            @args = []
            @queue = nil
            @at = nil
            @block = Proc.new {}
            set_expected_number(:exactly, 1)
          end

          def with(*args, &block)
            @args = args
            @block = block if block.present?
            self
          end

          def on_queue(queue)
            @queue = queue
            self
          end

          def at(date)
            @at = date
            self
          end

          def exactly(count)
            set_expected_number(:exactly, count)
            self
          end

          def at_least(count)
            set_expected_number(:at_least, count)
            self
          end

          def at_most(count)
            set_expected_number(:at_most, count)
            self
          end

          def times
            self
          end

          def once
            exactly(:once)
          end

          def twice
            exactly(:twice)
          end

          def thrice
            exactly(:thrice)
          end

          def failure_message
            "expected to enqueue #{base_message}".tap do |msg|
              if @unmatching_jobs.any?
                msg << "\nQueued jobs:"
                @unmatching_jobs.each do |job|
                  msg << "\n  #{base_job_message(job)}"
                end
              end
            end
          end

          def failure_message_when_negated
            "expected not to enqueue #{base_message}"
          end

          def message_expectation_modifier
            case @expectation_type
            when :exactly then "exactly"
            when :at_most then "at most"
            when :at_least then "at least"
            end
          end

          def supports_block_expectations?
            true
          end

        private

          def check(jobs)
            @matching_jobs, @unmatching_jobs = jobs.partition do |job|
              if arguments_match?(job) && other_attributes_match?(job)
                args = deserialize_arguments(job)
                @block.call(*args)
                true
              else
                false
              end
            end
            @matching_jobs_count = @matching_jobs.size

            case @expectation_type
            when :exactly then @expected_number == @matching_jobs_count
            when :at_most then @expected_number >= @matching_jobs_count
            when :at_least then @expected_number <= @matching_jobs_count
            end
          end

          def base_message
            "#{message_expectation_modifier} #{@expected_number} jobs,".tap do |msg|
              msg << " with #{@args}," if @args.any?
              msg << " on queue #{@queue}," if @queue
              msg << " at #{@at.inspect}," if @at
              msg << " but enqueued #{@matching_jobs_count}"
            end
          end

          def base_job_message(job)
            msg_parts = []
            msg_parts << "with #{deserialize_arguments(job)}" if job[:args].any?
            msg_parts << "on queue #{job[:queue]}" if job[:queue]
            msg_parts << "at #{Time.at(job[:at])}" if job[:at]

            "#{job[:job].name} job".tap do |msg|
              msg << " #{msg_parts.join(', ')}" if msg_parts.any?
            end
          end

          def arguments_match?(job)
            if @args.any?
              deserialized_args = deserialize_arguments(job)
              RSpec::Mocks::ArgumentListMatcher.new(*@args).args_match?(*deserialized_args)
            else
              true
            end
          end

          def other_attributes_match?(job)
            serialized_attributes.all? { |key, value| value == job[key] }
          end

          def serialized_attributes
            {}.tap do |attributes|
              attributes[:at]    = serialized_at if @at
              attributes[:queue] = @queue if @queue
              attributes[:job]   = @job if @job
            end
          end

          def serialized_at
            @at == :no_wait ? nil : @at.to_f
          end

          def set_expected_number(relativity, count)
            @expectation_type = relativity
            @expected_number = case count
                               when :once then 1
                               when :twice then 2
                               when :thrice then 3
                               else Integer(count)
                               end
          end

          def deserialize_arguments(job)
            ::ActiveJob::Arguments.deserialize(job[:args])
          rescue ::ActiveJob::DeserializationError
            job[:args]
          end

          def queue_adapter
            ::ActiveJob::Base.queue_adapter
          end
        end
        # rubocop: enable Style/ClassLength

        # @private
        class HaveEnqueuedJob < Base
          def initialize(job)
            super()
            @job = job
          end

          def matches?(proc)
            raise ArgumentError, "have_enqueued_job and enqueue_job only support block expectations" unless Proc === proc

            original_enqueued_jobs_count = queue_adapter.enqueued_jobs.count
            proc.call
            in_block_jobs = queue_adapter.enqueued_jobs.drop(original_enqueued_jobs_count)

            check(in_block_jobs)
          end
        end

        # @private
        class HaveBeenEnqueued < Base
          def matches?(job)
            @job = job
            check(queue_adapter.enqueued_jobs)
          end
        end
      end

      # @api public
      # Passes if a job has been enqueued inside block. May chain at_least, at_most or exactly to specify a number of times.
      #
      # @example
      #     expect {
      #       HeavyLiftingJob.perform_later
      #     }.to have_enqueued_job
      #
      #     # Using alias
      #     expect {
      #       HeavyLiftingJob.perform_later
      #     }.to enqueue_job
      #
      #     expect {
      #       HelloJob.perform_later
      #       HeavyLiftingJob.perform_later
      #     }.to have_enqueued_job(HelloJob).exactly(:once)
      #
      #     expect {
      #       3.times { HelloJob.perform_later }
      #     }.to have_enqueued_job(HelloJob).at_least(2).times
      #
      #     expect {
      #       HelloJob.perform_later
      #     }.to have_enqueued_job(HelloJob).at_most(:twice)
      #
      #     expect {
      #       HelloJob.perform_later
      #       HeavyLiftingJob.perform_later
      #     }.to have_enqueued_job(HelloJob).and have_enqueued_job(HeavyLiftingJob)
      #
      #     expect {
      #       HelloJob.set(wait_until: Date.tomorrow.noon, queue: "low").perform_later(42)
      #     }.to have_enqueued_job.with(42).on_queue("low").at(Date.tomorrow.noon)
      #
      #     expect {
      #       HelloJob.set(queue: "low").perform_later(42)
      #     }.to have_enqueued_job.with(42).on_queue("low").at(:no_wait)
      #
      #     expect {
      #       HelloJob.perform_later('rspec_rails', 'rails', 42)
      #     }.to have_enqueued_job.with { |from, to, times|
      #       # Perform more complex argument matching using dynamic arguments
      #       expect(from).to include "_#{to}"
      #     }
      def have_enqueued_job(job = nil)
        check_active_job_adapter
        ActiveJob::HaveEnqueuedJob.new(job)
      end
      alias_method :enqueue_job, :have_enqueued_job

      # @api public
      # Passes if a job has been enqueued. May chain at_least, at_most or exactly to specify a number of times.
      #
      # @example
      #     before { ActiveJob::Base.queue_adapter.enqueued_jobs.clear }
      #
      #     HeavyLiftingJob.perform_later
      #     expect(HeavyLiftingJob).to have_been_enqueued
      #
      #     HelloJob.perform_later
      #     HeavyLiftingJob.perform_later
      #     expect(HeavyLiftingJob).to have_been_enqueued.exactly(:once)
      #
      #     3.times { HelloJob.perform_later }
      #     expect(HelloJob).to have_been_enqueued.at_least(2).times
      #
      #     HelloJob.perform_later
      #     expect(HelloJob).to enqueue_job(HelloJob).at_most(:twice)
      #
      #     HelloJob.perform_later
      #     HeavyLiftingJob.perform_later
      #     expect(HelloJob).to have_been_enqueued
      #     expect(HeavyLiftingJob).to have_been_enqueued
      #
      #     HelloJob.set(wait_until: Date.tomorrow.noon, queue: "low").perform_later(42)
      #     expect(HelloJob).to have_been_enqueued.with(42).on_queue("low").at(Date.tomorrow.noon)
      #
      #     HelloJob.set(queue: "low").perform_later(42)
      #     expect(HelloJob).to have_been_enqueued.with(42).on_queue("low").at(:no_wait)
      def have_been_enqueued
        check_active_job_adapter
        ActiveJob::HaveBeenEnqueued.new
      end

    private

      # @private
      def check_active_job_adapter
        return if ::ActiveJob::QueueAdapters::TestAdapter === ::ActiveJob::Base.queue_adapter
        raise StandardError, "To use ActiveJob matchers set `ActiveJob::Base.queue_adapter = :test`"
      end
    end
  end
end
