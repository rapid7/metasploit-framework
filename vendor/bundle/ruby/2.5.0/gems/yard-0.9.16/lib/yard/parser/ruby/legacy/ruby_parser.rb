# frozen_string_literal: true
module YARD
  module Parser
    module Ruby
      module Legacy
        # Legacy Ruby parser
        # @since 0.5.6
        class RubyParser < Parser::Base
          def initialize(source, _filename)
            @source = source
          end

          def parse
            @parse ||= StatementList.new(@source)
            self
          end

          def tokenize
            @tokenize ||= TokenList.new(@source)
          end

          def enumerator
            @parse
          end

          def encoding_line; @parse.encoding_line end
          def shebang_line; @parse.shebang_line end
        end
      end
    end
  end
end
