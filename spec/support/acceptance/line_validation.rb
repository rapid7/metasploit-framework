module Acceptance
  ###
  # A utility object representing the validation of a a line of output generated
  # by the acceptance test suite.
  ###
  class LineValidation
    # @param [string|Array<String>] values A line string, or array of lines
    # @param [Object] options Additional options for configuring this failure, i.e. if it's a known flaky test result etc.
    def initialize(values, options = {})
      @values = Array(values)
      @options = options
    end

    def flatten
      @values.map { |value| self.class.new(value, @options) }
    end

    def value
      raise StandardError, 'More than one value present' if @values.length > 1

      @values[0]
    end

    # @return [boolean] returns true if the current failure applies under the current environment or the result is flaky, false otherwise.
    def flaky?
      !!@options.fetch(:flaky, true)
    end

    # @return [boolean] returns true if the current failure applies under the current environment or the result is flaky, false otherwise.
    def if?
      !!@options.fetch(:if, true)
    end
  end
end
