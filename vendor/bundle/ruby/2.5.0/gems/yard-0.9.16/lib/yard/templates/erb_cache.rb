# frozen_string_literal: true
module YARD
  module Templates
    # @since 0.5.4
    module ErbCache
      def self.method_for(filename)
        @methods ||= {}
        return @methods[filename] if @methods[filename]
        @methods[filename] = name = "_erb_cache_#{@methods.size}"
        erb = yield.src
        encoding = erb[/\A(#coding[:=].*\r?\n)/, 1] || ''
        module_eval "#{encoding}def #{name}; #{erb}; end", filename

        name
      end

      def self.clear!
        return unless defined?(@methods) && @methods
        @methods.clear
      end
    end
  end
end
