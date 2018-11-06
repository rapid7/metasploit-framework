RSpec::Support.require_rspec_support "ruby_features"

module RSpec
  # Consistent implementation for "cleaning" the caller method to strip out
  # non-rspec lines. This enables errors to be reported at the call site in
  # the code using the library, which is far more useful than the particular
  # internal method that raised an error.
  class CallerFilter
    RSPEC_LIBS = %w[
      core
      mocks
      expectations
      support
      matchers
      rails
    ]

    ADDITIONAL_TOP_LEVEL_FILES = %w[ autorun ]

    LIB_REGEX = %r{/lib/rspec/(#{(RSPEC_LIBS + ADDITIONAL_TOP_LEVEL_FILES).join('|')})(\.rb|/)}

    # rubygems/core_ext/kernel_require.rb isn't actually part of rspec (obviously) but we want
    # it ignored when we are looking for the first meaningful line of the backtrace outside
    # of RSpec. It can show up in the backtrace as the immediate first caller
    # when `CallerFilter.first_non_rspec_line` is called from the top level of a required
    # file, but it depends on if rubygems is loaded or not. We don't want to have to deal
    # with this complexity in our `RSpec.deprecate` calls, so we ignore it here.
    IGNORE_REGEX = Regexp.union(LIB_REGEX, "rubygems/core_ext/kernel_require.rb")

    if RSpec::Support::RubyFeatures.caller_locations_supported?
      # This supports args because it's more efficient when the caller specifies
      # these. It allows us to skip frames the caller knows are part of RSpec,
      # and to decrease the increment size if the caller is confident the line will
      # be found in a small number of stack frames from `skip_frames`.
      #
      # Note that there is a risk to passing a `skip_frames` value that is too high:
      # If it skippped the first non-rspec line, then this method would return the
      # 2nd or 3rd (or whatever) non-rspec line. Thus, you generally shouldn't pass
      # values for these parameters, particularly since most places that use this are
      # not hot spots (generally it gets used for deprecation warnings). However,
      # if you do have a hot spot that calls this, passing `skip_frames` can make
      # a significant difference. Just make sure that that particular use is tested
      # so that if the provided `skip_frames` changes to no longer be accurate in
      # such a way that would return the wrong stack frame, a test will fail to tell you.
      #
      # See benchmarks/skip_frames_for_caller_filter.rb for measurements.
      def self.first_non_rspec_line(skip_frames=3, increment=5)
        # Why a default `skip_frames` of 3?
        # By the time `caller_locations` is called below, the first 3 frames are:
        #   lib/rspec/support/caller_filter.rb:63:in `block in first_non_rspec_line'
        #   lib/rspec/support/caller_filter.rb:62:in `loop'
        #   lib/rspec/support/caller_filter.rb:62:in `first_non_rspec_line'

        # `caller` is an expensive method that scales linearly with the size of
        # the stack. The performance hit for fetching it in chunks is small,
        # and since the target line is probably near the top of the stack, the
        # overall improvement of a chunked search like this is significant.
        #
        # See benchmarks/caller.rb for measurements.

        # The default increment of 5 for this method are mostly arbitrary, but
        # is chosen to give good performance on the common case of creating a double.

        loop do
          stack = caller_locations(skip_frames, increment)
          raise "No non-lib lines in stack" unless stack

          line = stack.find { |l| l.path !~ IGNORE_REGEX }
          return line.to_s if line

          skip_frames += increment
          increment   *= 2 # The choice of two here is arbitrary.
        end
      end
    else
      # Earlier rubies do not support the two argument form of `caller`. This
      # fallback is logically the same, but slower.
      def self.first_non_rspec_line(*)
        caller.find { |line| line !~ IGNORE_REGEX }
      end
    end
  end
end
