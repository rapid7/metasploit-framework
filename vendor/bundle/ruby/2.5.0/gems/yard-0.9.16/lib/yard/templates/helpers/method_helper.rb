# frozen_string_literal: true
module YARD
  module Templates::Helpers
    # Helper methods for method objects.
    module MethodHelper
      # @return [String] formatted arguments for a method
      def format_args(object)
        return if object.parameters.nil?
        params = object.parameters
        if object.has_tag?(:yield) || object.has_tag?(:yieldparam)
          params.reject! do |param|
            param[0].to_s[0, 1] == "&" &&
              !object.tags(:param).any? {|t| t.name == param[0][1..-1] }
          end
        end

        if params.empty?
          ""
        else
          args = params.map do |n, v|
            v ? "#{n}#{n[-1, 1] == ':' ? '' : ' ='} #{v}" : n.to_s
          end.join(", ")
          h("(#{args})")
        end
      end

      # @return [String] formatted and linked return types for a method
      def format_return_types(object)
        return unless object.has_tag?(:return) && object.tag(:return).types
        return if object.tag(:return).types.empty?
        format_types [object.tag(:return).types.first], false
      end

      # @return [String] formatted block if one exists
      def format_block(object)
        if object.has_tag?(:yield) && object.tag(:yield).types
          params = object.tag(:yield).types
        elsif object.has_tag?(:yieldparam)
          params = object.tags(:yieldparam).map(&:name)
        elsif object.has_tag?(:yield)
          return "{ ... }"
        else
          params = nil
        end

        params ? h("{|" + params.join(", ") + "| ... }") : ""
      end

      # @return [String] formats line numbers for source code of an object
      def format_lines(object)
        return "" if object.source.nil? || object.line.nil?
        i = -1
        object.source.split(/\n/).map { object.line + (i += 1) }.join("\n")
      end

      # @return [String] formats source of an object
      def format_code(object, _show_lines = false)
        i = -1
        lines = object.source.split(/\n/)
        longestline = (object.line + lines.size).to_s.length
        lines.map do |line|
          lineno = object.line + (i += 1)
          (" " * (longestline - lineno.to_s.length)) + lineno.to_s + "    " + line
        end.join("\n")
      end

      # @return [String] formats source code of a constant value
      def format_constant(value)
        sp = value.split("\n").last[/^(\s+)/, 1]
        num = sp ? sp.size : 0
        html_syntax_highlight value.gsub(/^\s{#{num}}/, '')
      end
    end
  end
end
