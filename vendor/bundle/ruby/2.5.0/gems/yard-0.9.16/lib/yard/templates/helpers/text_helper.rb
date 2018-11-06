# frozen_string_literal: true
module YARD
  module Templates
    module Helpers
      # Helper methods for text template formats.
      module TextHelper
        # @return [String] escapes text
        def h(text)
          out = String.new("")
          text = resolve_links(text)
          text = text.split(/\n/)
          text.each_with_index do |line, i|
            out <<
              case line
              when /^\s*$/; "\n\n"
              when /^\s+\S/, /^=/; line + "\n"
              else; line + (text[i + 1] =~ /^\s+\S/ ? "\n" : " ")
              end
          end
          out
        end

        # @return [String] wraps text at +col+ columns.
        def wrap(text, col = 72)
          text.gsub(/(.{1,#{col}})( +|$\n?)|(.{1,#{col}})/, "\\1\\3\n")
        end

        # @return [String] indents +text+ by +len+ characters.
        def indent(text, len = 4)
          text.gsub(/^/, ' ' * len)
        end

        # @return [String] aligns a title to the right
        def title_align_right(text, col = 72)
          align_right(text, '-', col)
        end

        # @return [String] aligns text to the right
        def align_right(text, spacer = ' ', col = 72)
          text = text[0, col - 4] + '...' if (col - 1 - text.length) < 0
          spacer * (col - 1 - text.length) + " " + text
        end

        # @return [String] returns a horizontal rule for output
        def hr(col = 72, sep = "-")
          sep * col
        end

        # @return [String] the formatted signature for a method
        def signature(meth)
          # use first overload tag if it has a return type and method itself does not
          if !meth.tag(:return) && meth.tag(:overload) && meth.tag(:overload).tag(:return)
            meth = meth.tag(:overload)
          end

          type = options.default_return || ""
          rmeth = meth
          if !rmeth.has_tag?(:return) && rmeth.respond_to?(:object)
            rmeth = meth.object
          end
          if rmeth.tag(:return) && rmeth.tag(:return).types
            types = rmeth.tags(:return).map {|t| t.types ? t.types : [] }.flatten.uniq
            first = types.first
            if types.size == 2 && types.last == 'nil'
              type = first + '?'
            elsif types.size == 2 && types.last =~ /^(Array)?<#{Regexp.quote types.first}>$/
              type = first + '+'
            elsif types.size > 2
              type = [first, '...'].join(', ')
            elsif types == ['void'] && options.hide_void_return
              type = ""
            else
              type = types.join(", ")
            end
          end
          type = "(#{type})" if type.include?(',')
          type = " -> #{type} " unless type.empty?
          scope = meth.scope == :class ? "#{meth.namespace.name}." : "#{meth.namespace.name.to_s.downcase}."
          name = meth.name
          blk = format_block(meth)
          args = format_args(meth)
          extras = []
          extras_text = ''
          rw = meth.namespace.attributes[meth.scope][meth.name]
          if rw
            attname = [rw[:read] ? 'read' : nil, rw[:write] ? 'write' : nil].compact
            attname = attname.size == 1 ? attname.join('') + 'only' : nil
            extras << attname if attname
          end
          extras << meth.visibility if meth.visibility != :public
          extras_text = '(' + extras.join(", ") + ')' unless extras.empty?
          title = "%s%s%s %s%s%s" % [scope, name, args, blk, type, extras_text]
          title.gsub(/\s+/, ' ')
        end

        private

        def resolve_links(text)
          text.gsub(/(\\|!)?\{(?!\})(\S+?)(?:\s([^\}]*?\S))?\}(?=[\W]|$)/m) do |_str|
            escape = $1
            name = $2
            title = $3
            match = $&
            next(match[1..-1]) if escape
            next(match) if name[0, 1] == '|'
            linkify(name, title)
          end
        end
      end
    end
  end
end
