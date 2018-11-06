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
        :debug => "\e[1;37;44m",
        
        :annotation => "\e[34m",
        :attribute_name => "\e[35m",
        :attribute_value => "\e[31m",
        :binary => {
          :self => "\e[31m",
          :char => "\e[1;31m",
          :delimiter => "\e[1;31m",
        },
        :char => {
          :self => "\e[35m",
          :delimiter => "\e[1;35m"
        },
        :class => "\e[1;35;4m",
        :class_variable => "\e[36m",
        :color => "\e[32m",
        :comment => {
          :self => "\e[1;30m",
          :char => "\e[37m",
          :delimiter => "\e[37m",
        },
        :constant => "\e[1;34;4m",
        :decorator => "\e[35m",
        :definition => "\e[1;33m",
        :directive => "\e[33m",
        :docstring => "\e[31m",
        :doctype => "\e[1;34m",
        :done => "\e[1;30;2m",
        :entity => "\e[31m",
        :error => "\e[1;37;41m",
        :exception => "\e[1;31m",
        :float => "\e[1;35m",
        :function => "\e[1;34m",
        :global_variable => "\e[1;32m",
        :hex => "\e[1;36m",
        :id => "\e[1;34m",
        :include => "\e[31m",
        :integer => "\e[1;34m",
        :imaginary => "\e[1;34m",
        :important => "\e[1;31m",
        :key => {
          :self => "\e[35m",
          :char => "\e[1;35m",
          :delimiter => "\e[1;35m",
        },
        :keyword => "\e[32m",
        :label => "\e[1;33m",
        :local_variable => "\e[33m",
        :namespace => "\e[1;35m",
        :octal => "\e[1;34m",
        :predefined => "\e[36m",
        :predefined_constant => "\e[1;36m",
        :predefined_type => "\e[1;32m",
        :preprocessor => "\e[1;36m",
        :pseudo_class => "\e[1;34m",
        :regexp => {
          :self => "\e[35m",
          :delimiter => "\e[1;35m",
          :modifier => "\e[35m",
          :char => "\e[1;35m",
        },
        :reserved => "\e[32m",
        :shell => {
          :self => "\e[33m",
          :char => "\e[1;33m",
          :delimiter => "\e[1;33m",
          :escape => "\e[1;33m",
        },
        :string => {
          :self => "\e[31m",
          :modifier => "\e[1;31m",
          :char => "\e[1;35m",
          :delimiter => "\e[1;31m",
          :escape => "\e[1;31m",
        },
        :symbol => {
          :self => "\e[33m",
          :delimiter => "\e[1;33m",
        },
        :tag => "\e[32m",
        :type => "\e[1;34m",
        :value => "\e[36m",
        :variable => "\e[34m",
        
        :insert => {
          :self => "\e[42m",
          :insert => "\e[1;32;42m",
          :eyecatcher => "\e[102m",
        },
        :delete => {
          :self => "\e[41m",
          :delete => "\e[1;31;41m",
          :eyecatcher => "\e[101m",
        },
        :change => {
          :self => "\e[44m",
          :change => "\e[37;44m",
        },
        :head => {
          :self => "\e[45m",
          :filename => "\e[37;45m"
        },
      }
      
      TOKEN_COLORS[:keyword] = TOKEN_COLORS[:reserved]
      TOKEN_COLORS[:method] = TOKEN_COLORS[:function]
      TOKEN_COLORS[:escape] = TOKEN_COLORS[:delimiter]
      
    protected
      
      def setup(options)
        super
        @opened = []
        @color_scopes = [TOKEN_COLORS]
      end
      
    public
      
      def text_token text, kind
        if color = @color_scopes.last[kind]
          color = color[:self] if color.is_a? Hash
          
          @out << color
          @out << (text.index("\n") ? text.gsub("\n", "\e[0m\n" + color) : text)
          @out << "\e[0m"
          if outer_color = @color_scopes.last[:self]
            @out << outer_color
          end
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
        if @opened.pop
          @color_scopes.pop
          @out << "\e[0m"
          if outer_color = @color_scopes.last[:self]
            @out << outer_color
          end
        end
      end
      
      def end_line kind
        @out << (@line_filler ||= "\t" * 100)
        end_group kind
      end
      
    private
      
      def open_token kind
        if color = @color_scopes.last[kind]
          if color.is_a? Hash
            @color_scopes << color
            color[:self]
          else
            @color_scopes << @color_scopes.last
            color
          end
        else
          @color_scopes << @color_scopes.last
          ''
        end
      end
    end
  end
end
