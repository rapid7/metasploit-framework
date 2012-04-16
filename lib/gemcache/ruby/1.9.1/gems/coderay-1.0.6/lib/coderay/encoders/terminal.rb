module CodeRay
  module Encoders
    
    # Outputs code highlighted for a color terminal.
    # 
    # Note: This encoder is in beta. It currently doesn't use the Styles.
    # 
    # Alias: +term+
    # 
    # == Authors & License
    # 
    # By Rob Aldred (http://robaldred.co.uk)
    # 
    # Based on idea by Nathan Weizenbaum (http://nex-3.com)
    # 
    # MIT License (http://www.opensource.org/licenses/mit-license.php)
    class Terminal < Encoder
      
      register_for :terminal
      
      TOKEN_COLORS = {
        :annotation => '35',
        :attribute_name => '33',
        :attribute_value => '31',
        :binary => '1;35',
        :char => {
          :self => '36', :delimiter => '1;34'
        },
        :class => '1;35',
        :class_variable => '36',
        :color => '32',
        :comment => '37',
        :complex => '1;34',
        :constant => ['1;34', '4'],
        :decoration => '35',
        :definition => '1;32',
        :directive => ['32', '4'],
        :doc => '46',
        :doctype => '1;30',
        :doc_string => ['31', '4'],
        :entity => '33',
        :error => ['1;33', '41'],
        :exception => '1;31',
        :float => '1;35',
        :function => '1;34',
        :global_variable => '42',
        :hex => '1;36',
        :include => '33',
        :integer => '1;34',
        :key => '35',
        :label => '1;15',
        :local_variable => '33',
        :octal => '1;35',
        :operator_name => '1;29',
        :predefined_constant => '1;36',
        :predefined_type => '1;30',
        :predefined => ['4', '1;34'],
        :preprocessor => '36',
        :pseudo_class => '1;34',
        :regexp => {
          :self => '31',
          :content => '31',
          :delimiter => '1;29',
          :modifier => '35',
          :function => '1;29'
        },
        :reserved => '1;31',
        :shell => {
          :self => '42',
          :content => '1;29',
          :delimiter => '37',
        },
        :string => {
          :self => '32',
          :modifier => '1;32',
          :escape => '1;36',
          :delimiter => '1;32',
        },
        :symbol => '1;32',
        :tag => '1;34',
        :type => '1;34',
        :value => '36',
        :variable => '1;34',
        
        :insert => '42',
        :delete => '41',
        :change => '44',
        :head => '45'
      }
      TOKEN_COLORS[:keyword] = TOKEN_COLORS[:reserved]
      TOKEN_COLORS[:method] = TOKEN_COLORS[:function]
      TOKEN_COLORS[:imaginary] = TOKEN_COLORS[:complex]
      TOKEN_COLORS[:begin_group] = TOKEN_COLORS[:end_group] =
        TOKEN_COLORS[:escape] = TOKEN_COLORS[:delimiter]
      
    protected
      
      def setup(options)
        super
        @opened = []
        @subcolors = nil
      end
      
    public
      
      def text_token text, kind
        if color = (@subcolors || TOKEN_COLORS)[kind]
          if Hash === color
            if color[:self]
              color = color[:self]
            else
              @out << text
              return
            end
          end
          
          @out << ansi_colorize(color)
          @out << text.gsub("\n", ansi_clear + "\n" + ansi_colorize(color))
          @out << ansi_clear
          @out << ansi_colorize(@subcolors[:self]) if @subcolors && @subcolors[:self]
        else
          @out << text
        end
      end
      
      def begin_group kind
        @opened << kind
        @out << open_token(kind)
      end
      alias begin_line begin_group
      
      def end_group kind
        if @opened.empty?
          # nothing to close
        else
          @opened.pop
          @out << ansi_clear
          @out << open_token(@opened.last)
        end
      end
      
      def end_line kind
        if @opened.empty?
          # nothing to close
        else
          @opened.pop
          # whole lines to be highlighted,
          # eg. added/modified/deleted lines in a diff
          @out << "\t" * 100 + ansi_clear
          @out << open_token(@opened.last)
        end
      end
      
    private
      
      def open_token kind
        if color = TOKEN_COLORS[kind]
          if Hash === color
            @subcolors = color
            ansi_colorize(color[:self]) if color[:self]
          else
            @subcolors = {}
            ansi_colorize(color)
          end
        else
          @subcolors = nil
          ''
        end
      end
      
      def ansi_colorize(color)
        Array(color).map { |c| "\e[#{c}m" }.join
      end
      def ansi_clear
        ansi_colorize(0)
      end
    end
  end
end