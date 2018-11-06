# frozen_string_literal: true

module SimpleCov
  #
  # Base filter class. Inherit from this to create custom filters,
  # and overwrite the passes?(source_file) instance method
  #
  # # A sample class that rejects all source files.
  # class StupidFilter < SimpleCov::Filter
  #   def passes?(source_file)
  #     false
  #   end
  # end
  #
  class Filter
    attr_reader :filter_argument
    def initialize(filter_argument)
      @filter_argument = filter_argument
    end

    def matches?(_)
      raise "The base filter class is not intended for direct use"
    end

    def passes?(source_file)
      warn "#{Kernel.caller.first}: [DEPRECATION] #passes? is deprecated. Use #matches? instead."
      matches?(source_file)
    end

    def self.build_filter(filter_argument)
      return filter_argument if filter_argument.is_a?(SimpleCov::Filter)
      class_for_argument(filter_argument).new(filter_argument)
    end

    def self.class_for_argument(filter_argument)
      if filter_argument.is_a?(String)
        SimpleCov::StringFilter
      elsif filter_argument.is_a?(Regexp)
        SimpleCov::RegexFilter
      elsif filter_argument.is_a?(Array)
        SimpleCov::ArrayFilter
      elsif filter_argument.is_a?(Proc)
        SimpleCov::BlockFilter
      else
        raise ArgumentError, "You have provided an unrecognized filter type"
      end
    end
  end

  class StringFilter < SimpleCov::Filter
    # Returns true when the given source file's filename matches the
    # string configured when initializing this Filter with StringFilter.new('somestring)
    def matches?(source_file)
      source_file.project_filename.include?(filter_argument)
    end
  end

  class RegexFilter < SimpleCov::Filter
    # Returns true when the given source file's filename matches the
    # regex configured when initializing this Filter with RegexFilter.new(/someregex/)
    def matches?(source_file)
      (source_file.project_filename =~ filter_argument)
    end
  end

  class BlockFilter < SimpleCov::Filter
    # Returns true if the block given when initializing this filter with BlockFilter.new {|src_file| ... }
    # returns true for the given source file.
    def matches?(source_file)
      filter_argument.call(source_file)
    end
  end

  class ArrayFilter < SimpleCov::Filter
    def initialize(filter_argument)
      filter_objects = filter_argument.map do |arg|
        Filter.build_filter(arg)
      end

      super(filter_objects)
    end

    # Returns true if any of the filters in the array match the given source file.
    # Configure this Filter like StringFilter.new(['some/path', /^some_regex/, Proc.new {|src_file| ... }])
    def matches?(source_files_list)
      filter_argument.any? do |arg|
        arg.matches?(source_files_list)
      end
    end
  end
end
