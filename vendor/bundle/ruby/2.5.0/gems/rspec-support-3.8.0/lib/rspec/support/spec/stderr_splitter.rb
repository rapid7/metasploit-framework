require 'stringio'

module RSpec
  module Support
    class StdErrSplitter
      def initialize(original)
        @orig_stderr    = original
        @output_tracker = ::StringIO.new
      end

      respond_to_name = (::RUBY_VERSION.to_f < 1.9) ? :respond_to? : :respond_to_missing?
      define_method respond_to_name do |*args|
        @orig_stderr.respond_to?(*args) || super(*args)
      end

      def method_missing(name, *args, &block)
        @output_tracker.__send__(name, *args, &block) if @output_tracker.respond_to?(name)
        @orig_stderr.__send__(name, *args, &block)
      end

      def ==(other)
        @orig_stderr == other
      end

      def reopen(*args)
        reset!
        @orig_stderr.reopen(*args)
      end

      # To work around JRuby error:
      # can't convert RSpec::Support::StdErrSplitter into String
      def to_io
        @orig_stderr.to_io
      end

      # To work around JRuby error:
      # TypeError: $stderr must have write method, RSpec::StdErrSplitter given
      def write(line)
        return if line =~ %r{^\S+/gems/\S+:\d+: warning:} # http://rubular.com/r/kqeUIZOfPG

        @orig_stderr.write(line)
        @output_tracker.write(line)
      end

      def has_output?
        !output.empty?
      end

      def reset!
        @output_tracker = ::StringIO.new
      end

      def verify_no_warnings!
        raise "Warnings were generated: #{output}" if has_output?
        reset!
      end

      def output
        @output_tracker.string
      end
    end
  end
end
