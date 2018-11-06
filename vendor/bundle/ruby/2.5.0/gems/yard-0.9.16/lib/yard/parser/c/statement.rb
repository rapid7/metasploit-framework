# frozen_string_literal: true
module YARD
  module Parser
    module C
      class Statement
        attr_accessor :source
        attr_accessor :line
        attr_accessor :file

        # @deprecated Groups are now defined by directives
        # @see Tags::GroupDirective
        attr_accessor :group

        attr_accessor :comments_hash_flag

        def initialize(source, file = nil, line = nil)
          @source = source
          @file = file
          @line = line
        end

        def line_range
          line...(line + source.count("\n"))
        end

        def comments_range
          comments.line_range
        end

        def first_line
          source.split(/\n/).first
        end

        def show
          "\t#{line}: #{first_line}"
        end
      end

      class BodyStatement < Statement
        attr_accessor :comments
      end

      class ToplevelStatement < Statement
        attr_accessor :block
        attr_accessor :declaration
        attr_accessor :comments
      end

      class Comment < Statement
        include CommentParser

        attr_accessor :type
        attr_accessor :overrides
        attr_accessor :statement

        def initialize(source, file = nil, line = nil)
          super(parse_comments(source), file, line)
        end

        def comments; self end
      end
    end
  end
end
