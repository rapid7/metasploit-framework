class Pry
  class Command::Cat
    class AbstractFormatter
      include Pry::Helpers::CommandHelpers
      include Pry::Helpers::BaseHelpers

      private
      def decorate(content)
        content.code_type = code_type
        content.between(*between_lines).
          with_line_numbers(use_line_numbers?).highlighted
      end

      def code_type
        opts[:type] || :ruby
      end

      def use_line_numbers?
        opts.present?(:'line-numbers') || opts.present?(:ex)
      end

      def between_lines
        [opts[:start] || 1, opts[:end] || -1]
      end
    end
  end
end
