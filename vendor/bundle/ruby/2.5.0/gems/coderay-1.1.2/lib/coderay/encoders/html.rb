require 'set'

module CodeRay
module Encoders
  
  # = HTML Encoder
  #
  # This is CodeRay's most important highlighter:
  # It provides save, fast XHTML generation and CSS support.
  #
  # == Usage
  #
  #  require 'coderay'
  #  puts CodeRay.scan('Some /code/', :ruby).html  #-> a HTML page
  #  puts CodeRay.scan('Some /code/', :ruby).html(:wrap => :span)
  #  #-> <span class="CodeRay"><span class="co">Some</span> /code/</span>
  #  puts CodeRay.scan('Some /code/', :ruby).span  #-> the same
  #  
  #  puts CodeRay.scan('Some code', :ruby).html(
  #    :wrap => nil,
  #    :line_numbers => :inline,
  #    :css => :style
  #  )
  #
  # == Options
  #
  # === :tab_width
  # Convert \t characters to +n+ spaces (a number or false.)
  # false will keep tab characters untouched.
  # 
  # Default: 8
  #
  # === :css
  # How to include the styles; can be :class or :style.
  #
  # Default: :class
  #
  # === :wrap
  # Wrap in :page, :div, :span or nil.
  #
  # You can also use Encoders::Div and Encoders::Span.
  #
  # Default: nil
  #
  # === :title
  # 
  # The title of the HTML page (works only when :wrap is set to :page.)
  #
  # Default: 'CodeRay output'
  #
  # === :break_lines
  # 
  # Split multiline blocks at line breaks.
  # Forced to true if :line_numbers option is set to :inline.
  #
  # Default: false
  #
  # === :line_numbers
  # Include line numbers in :table, :inline, or nil (no line numbers)
  #
  # Default: nil
  #
  # === :line_number_anchors
  # Adds anchors and links to the line numbers. Can be false (off), true (on),
  # or a prefix string that will be prepended to the anchor name.
  #
  # The prefix must consist only of letters, digits, and underscores.
  #
  # Default: true, default prefix name: "line"
  #
  # === :line_number_start
  # Where to start with line number counting.
  #
  # Default: 1
  #
  # === :bold_every
  # Make every +n+-th number appear bold.
  #
  # Default: 10
  #
  # === :highlight_lines
  # 
  # Highlights certain line numbers.
  # Can be any Enumerable, typically just an Array or Range, of numbers.
  # 
  # Bolding is deactivated when :highlight_lines is set. It only makes sense
  # in combination with :line_numbers.
  #
  # Default: nil
  #
  # === :hint
  # Include some information into the output using the title attribute.
  # Can be :info (show token kind on mouse-over), :info_long (with full path)
  # or :debug (via inspect).
  #
  # Default: false
  class HTML < Encoder
    
    register_for :html
    
    FILE_EXTENSION = 'snippet.html'
    
    DEFAULT_OPTIONS = {
      :tab_width => 8,
      
      :css   => :class,
      :style => :alpha,
      :wrap  => nil,
      :title => 'CodeRay output',
      
      :break_lines => false,
      
      :line_numbers        => nil,
      :line_number_anchors => 'n',
      :line_number_start   => 1,
      :bold_every          => 10,
      :highlight_lines     => nil,
      
      :hint => false,
    }
    
    autoload :Output,    CodeRay.coderay_path('encoders', 'html', 'output')
    autoload :CSS,       CodeRay.coderay_path('encoders', 'html', 'css')
    autoload :Numbering, CodeRay.coderay_path('encoders', 'html', 'numbering')
    
    attr_reader :css
    
  protected
    
    def self.make_html_escape_hash
      {
        '&' => '&amp;',
        '"' => '&quot;',
        '>' => '&gt;',
        '<' => '&lt;',
        # "\t" => will be set to ' ' * options[:tab_width] during setup
      }.tap do |hash|
        # Escape ASCII control codes except \x9 == \t and \xA == \n.
        (Array(0x00..0x8) + Array(0xB..0x1F)).each { |invalid| hash[invalid.chr] = ' ' }
      end
    end
    
    HTML_ESCAPE = make_html_escape_hash
    HTML_ESCAPE_PATTERN = /[\t"&><\0-\x8\xB-\x1F]/
    
    TOKEN_KIND_TO_INFO = Hash.new do |h, kind|
      h[kind] = kind.to_s.gsub(/_/, ' ').gsub(/\b\w/) { $&.capitalize }
    end
    
    TRANSPARENT_TOKEN_KINDS = Set[
      :delimiter, :modifier, :content, :escape, :inline_delimiter,
    ]
    
    # Generate a hint about the given +kinds+ in a +hint+ style.
    #
    # +hint+ may be :info, :info_long or :debug.
    def self.token_path_to_hint hint, kinds
      kinds = Array kinds
      title =
        case hint
        when :info
          kinds = kinds[1..-1] if TRANSPARENT_TOKEN_KINDS.include? kinds.first
          TOKEN_KIND_TO_INFO[kinds.first]
        when :info_long
          kinds.reverse.map { |kind| TOKEN_KIND_TO_INFO[kind] }.join('/')
        when :debug
          kinds.inspect
        end
      title ? " title=\"#{title}\"" : ''
    end
    
    def setup options
      super
      
      check_options! options
      
      if options[:wrap] || options[:line_numbers]
        @real_out = @out
        @out = ''.dup
      end
      
      @break_lines = (options[:break_lines] == true)
      
      @HTML_ESCAPE = HTML_ESCAPE.merge("\t" => options[:tab_width] ? ' ' * options[:tab_width] : "\t")
      
      @opened = []
      @last_opened = nil
      @css = CSS.new options[:style]
      
      @span_for_kinds = make_span_for_kinds(options[:css], options[:hint])
      
      @set_last_opened = options[:hint] || options[:css] == :style
    end
    
    def finish options
      unless @opened.empty?
        @out << '</span>' while @opened.pop
        @last_opened = nil
      end
      
      if @out.respond_to? :to_str
        @out.extend Output
        @out.css = @css
        if options[:line_numbers]
          Numbering.number! @out, options[:line_numbers], options
        end
        @out.wrap! options[:wrap]
        @out.apply_title! options[:title]
      end
      
      if defined?(@real_out) && @real_out
        @real_out << @out
        @out = @real_out
      end
      
      super
    end
    
  public
    
    def text_token text, kind
      style = @span_for_kinds[@last_opened ? [kind, *@opened] : kind]
      
      text = text.gsub(/#{HTML_ESCAPE_PATTERN}/o) { |m| @HTML_ESCAPE[m] } if text =~ /#{HTML_ESCAPE_PATTERN}/o
      text = break_lines(text, style) if @break_lines && (style || @opened.size > 0) && text.index("\n")
      
      if style
        @out << style << text << '</span>'
      else
        @out << text
      end
    end
    
    # token groups, eg. strings
    def begin_group kind
      @out << (@span_for_kinds[@last_opened ? [kind, *@opened] : kind] || '<span>')
      @opened << kind
      @last_opened = kind if @set_last_opened
    end
    
    def end_group kind
      check_group_nesting 'token group', kind if $CODERAY_DEBUG
      close_span
    end
    
    # whole lines to be highlighted, eg. a deleted line in a diff
    def begin_line kind
      if style = @span_for_kinds[@last_opened ? [kind, *@opened] : kind]
        if style['class="']
          @out << style.sub('class="', 'class="line ')
        else
          @out << style.sub('>', ' class="line">')
        end
      else
        @out << '<span class="line">'
      end
      @opened << kind
      @last_opened = kind if @options[:css] == :style
    end
    
    def end_line kind
      check_group_nesting 'line', kind if $CODERAY_DEBUG
      close_span
    end
    
  protected
    
    def check_options! options
      unless [false, nil, :debug, :info, :info_long].include? options[:hint]
        raise ArgumentError, "Unknown value %p for :hint; expected :info, :info_long, :debug, false, or nil." % [options[:hint]]
      end
      
      unless [:class, :style].include? options[:css]
        raise ArgumentError, 'Unknown value %p for :css.' % [options[:css]]
      end
      
      options[:break_lines] = true if options[:line_numbers] == :inline
    end
    
    def css_class_for_kinds kinds
      TokenKinds[kinds.is_a?(Symbol) ? kinds : kinds.first]
    end
    
    def style_for_kinds kinds
      css_classes = kinds.is_a?(Array) ? kinds.map { |c| TokenKinds[c] } : [TokenKinds[kinds]]
      @css.get_style_for_css_classes css_classes
    end
    
    def make_span_for_kinds method, hint
      Hash.new do |h, kinds|
        begin
          css_class = css_class_for_kinds(kinds)
          title     = HTML.token_path_to_hint hint, kinds if hint
          
          if css_class || title
            if method == :style
              style = style_for_kinds(kinds)
              "<span#{title}#{" style=\"#{style}\"" if style}>"
            else
              "<span#{title}#{" class=\"#{css_class}\"" if css_class}>"
            end
          end
        end.tap do |span|
          h.clear if h.size >= 100
          h[kinds] = span
        end
      end
    end
    
    def check_group_nesting name, kind
      if @opened.empty? || @opened.last != kind
        warn "Malformed token stream: Trying to close a #{name} (%p) that is not open. Open are: %p." % [kind, @opened[1..-1]]
      end
    end
    
    def break_lines text, style
      reopen = ''.dup
      @opened.each_with_index do |kind, index|
        reopen << (@span_for_kinds[index > 0 ? [kind, *@opened[0...index]] : kind] || '<span>')
      end
      text.gsub("\n", "#{'</span>' * @opened.size}#{'</span>' if style}\n#{reopen}#{style}")
    end
    
    def close_span
      if @opened.pop
        @out << '</span>'
        @last_opened = @opened.last if @last_opened
      end
    end
  end
  
end
end
