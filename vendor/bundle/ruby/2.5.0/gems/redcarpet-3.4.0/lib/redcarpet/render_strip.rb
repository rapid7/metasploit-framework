module Redcarpet
  module Render
    # Markdown-stripping renderer. Turns Markdown into plaintext
    # Thanks to @toupeira (Markus Koller)
    class StripDown < Base
      # Methods where the first argument is the text content
      [
        # block-level calls
        :block_code, :block_quote,
        :block_html, :list, :list_item,

        # span-level calls
        :autolink, :codespan, :double_emphasis,
        :emphasis, :underline, :raw_html,
        :triple_emphasis, :strikethrough,
        :superscript, :highlight,

        # footnotes
        :footnotes, :footnote_def, :footnote_ref,

        # low level rendering
        :entity, :normal_text
      ].each do |method|
        define_method method do |*args|
          args.first
        end
      end

      # Other methods where we don't return only a specific argument
      def link(link, title, content)
        "#{content} (#{link})"
      end

      def image(link, title, content)
        content &&= content + " "
        "#{content}#{link}"
      end

      def paragraph(text)
        text + "\n"
      end

      def header(text, header_level)
        text + "\n"
      end

      def table(header, body)
        "#{header}#{body}"
      end

      def table_row(content)
        content + "\n"
      end

      def table_cell(content, alignment)
        content + "\t"
      end
    end
  end
end
