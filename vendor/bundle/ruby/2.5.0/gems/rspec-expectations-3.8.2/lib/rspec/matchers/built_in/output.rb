require 'stringio'

module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `output`.
      # Not intended to be instantiated directly.
      class Output < BaseMatcher
        def initialize(expected)
          @expected        = expected
          @actual          = ""
          @block           = nil
          @stream_capturer = NullCapture
        end

        def matches?(block)
          @block = block
          return false unless Proc === block
          @actual = @stream_capturer.capture(block)
          @expected ? values_match?(@expected, @actual) : captured?
        end

        def does_not_match?(block)
          !matches?(block) && Proc === block
        end

        # @api public
        # Tells the matcher to match against stdout.
        # Works only when the main Ruby process prints to stdout
        def to_stdout
          @stream_capturer = CaptureStdout
          self
        end

        # @api public
        # Tells the matcher to match against stderr.
        # Works only when the main Ruby process prints to stderr
        def to_stderr
          @stream_capturer = CaptureStderr
          self
        end

        # @api public
        # Tells the matcher to match against stdout.
        # Works when subprocesses print to stdout as well.
        # This is significantly (~30x) slower than `to_stdout`
        def to_stdout_from_any_process
          @stream_capturer = CaptureStreamToTempfile.new("stdout", $stdout)
          self
        end

        # @api public
        # Tells the matcher to match against stderr.
        # Works when subprocesses print to stderr as well.
        # This is significantly (~30x) slower than `to_stderr`
        def to_stderr_from_any_process
          @stream_capturer = CaptureStreamToTempfile.new("stderr", $stderr)
          self
        end

        # @api private
        # @return [String]
        def failure_message
          "expected block to #{description}, but #{positive_failure_reason}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected block to not #{description}, but #{negative_failure_reason}"
        end

        # @api private
        # @return [String]
        def description
          if @expected
            "output #{description_of @expected} to #{@stream_capturer.name}"
          else
            "output to #{@stream_capturer.name}"
          end
        end

        # @api private
        # @return [Boolean]
        def diffable?
          true
        end

        # @api private
        # Indicates this matcher matches against a block.
        # @return [True]
        def supports_block_expectations?
          true
        end

      private

        def captured?
          @actual.length > 0
        end

        def positive_failure_reason
          return "was not a block" unless Proc === @block
          return "output #{actual_output_description}" if @expected
          "did not"
        end

        def negative_failure_reason
          return "was not a block" unless Proc === @block
          "output #{actual_output_description}"
        end

        def actual_output_description
          return "nothing" unless captured?
          actual_formatted
        end
      end

      # @private
      module NullCapture
        def self.name
          "some stream"
        end

        def self.capture(_block)
          raise "You must chain `to_stdout` or `to_stderr` off of the `output(...)` matcher."
        end
      end

      # @private
      module CaptureStdout
        def self.name
          'stdout'
        end

        def self.capture(block)
          captured_stream = StringIO.new

          original_stream = $stdout
          $stdout = captured_stream

          block.call

          captured_stream.string
        ensure
          $stdout = original_stream
        end
      end

      # @private
      module CaptureStderr
        def self.name
          'stderr'
        end

        def self.capture(block)
          captured_stream = StringIO.new

          original_stream = $stderr
          $stderr = captured_stream

          block.call

          captured_stream.string
        ensure
          $stderr = original_stream
        end
      end

      # @private
      class CaptureStreamToTempfile < Struct.new(:name, :stream)
        def capture(block)
          # We delay loading tempfile until it is actually needed because
          # we want to minimize stdlibs loaded so that users who use a
          # portion of the stdlib can't have passing specs while forgetting
          # to load it themselves. `CaptureStreamToTempfile` is rarely used
          # and `tempfile` pulls in a bunch of things (delegate, tmpdir,
          # thread, fileutils, etc), so it's worth delaying it until this point.
          require 'tempfile'

          original_stream = stream.clone
          captured_stream = Tempfile.new(name)

          begin
            captured_stream.sync = true
            stream.reopen(captured_stream)
            block.call
            captured_stream.rewind
            captured_stream.read
          ensure
            stream.reopen(original_stream)
            captured_stream.close
            captured_stream.unlink
          end
        end
      end
    end
  end
end
