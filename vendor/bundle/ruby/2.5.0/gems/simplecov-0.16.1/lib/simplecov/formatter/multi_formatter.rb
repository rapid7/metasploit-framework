# frozen_string_literal: true

module SimpleCov
  module Formatter
    class MultiFormatter
      module InstanceMethods
        def format(result)
          formatters.map do |formatter|
            begin
              formatter.new.format(result)
            rescue => e
              STDERR.puts("Formatter #{formatter} failed with #{e.class}: #{e.message} (#{e.backtrace.first})")
              nil
            end
          end
        end
      end

      def self.new(formatters = nil)
        Class.new do
          define_method :formatters do
            @formatters ||= Array(formatters)
          end
          include InstanceMethods
        end
      end

      def self.[](*args)
        warn "#{Kernel.caller.first}: [DEPRECATION] ::[] is deprecated. Use ::new instead."
        new(Array([*args]))
      end
    end
  end
end
