module Treetop
  module Compiler
    class AtomicExpression < ParsingExpression
      def inline_modules
        []
      end
      
      def single_quote(string)
	# Double any backslashes, then backslash any single-quotes:
	"'#{string.gsub(/\\/) { '\\\\' }.gsub(/'/) { "\\'"}}'"
      end
    end
  end
end
