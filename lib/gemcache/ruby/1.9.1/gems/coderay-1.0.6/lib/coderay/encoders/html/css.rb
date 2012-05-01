module CodeRay
module Encoders

  class HTML
    class CSS  # :nodoc:

      attr :stylesheet

      def CSS.load_stylesheet style = nil
        CodeRay::Styles[style]
      end

      def initialize style = :default
        @classes = Hash.new
        style = CSS.load_stylesheet style
        @stylesheet = [
          style::CSS_MAIN_STYLES,
          style::TOKEN_COLORS.gsub(/^(?!$)/, '.CodeRay ')
        ].join("\n")
        parse style::TOKEN_COLORS
      end

      def get_style styles
        cl = @classes[styles.first]
        return '' unless cl
        style = ''
        1.upto styles.size do |offset|
          break if style = cl[styles[offset .. -1]]
        end
        # warn 'Style not found: %p' % [styles] if style.empty?
        return style
      end

    private

      CSS_CLASS_PATTERN = /
        (                    # $1 = selectors
          (?:
            (?: \s* \. [-\w]+ )+
            \s* ,?
          )+
        )
        \s* \{ \s*
        ( [^\}]+ )?          # $2 = style
        \s* \} \s*
      |
        ( [^\n]+ )           # $3 = error
      /mx
      def parse stylesheet
        stylesheet.scan CSS_CLASS_PATTERN do |selectors, style, error|
          raise "CSS parse error: '#{error.inspect}' not recognized" if error
          for selector in selectors.split(',')
            classes = selector.scan(/[-\w]+/)
            cl = classes.pop
            @classes[cl] ||= Hash.new
            @classes[cl][classes] = style.to_s.strip.delete(' ').chomp(';')
          end
        end
      end

    end
  end

end
end
