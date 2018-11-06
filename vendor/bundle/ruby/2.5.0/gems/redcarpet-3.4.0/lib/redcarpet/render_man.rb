module Redcarpet
  module Render
    class ManPage < Base

      def normal_text(text)
        text.gsub('-', '\\-').strip
      end

      def block_code(code, language)
        "\n.nf\n#{normal_text(code)}\n.fi\n"
      end

      def codespan(code)
        block_code(code, nil)
      end

      def header(title, level)
        case level
        when 1
          "\n.TH #{title}\n"

        when 2
          "\n.SH #{title}\n"

        when 3
          "\n.SS #{title}\n"
        end
      end

      def double_emphasis(text)
        "\\fB#{text}\\fP"
      end

      def emphasis(text)
        "\\fI#{text}\\fP"
      end

      def linebreak
        "\n.LP\n"
      end

      def paragraph(text)
        "\n.TP\n#{text}\n"
      end

      def list(content, list_type)
        case list_type
        when :ordered
          "\n\n.nr step 0 1\n#{content}\n"
        when :unordered
          "\n.\n#{content}\n"
        end
      end

      def list_item(content, list_type)
        case list_type
        when :ordered
          ".IP \\n+[step]\n#{content.strip}\n"
        when :unordered
          ".IP \\[bu] 2 \n#{content.strip}\n"
        end
      end
    end
  end
end
