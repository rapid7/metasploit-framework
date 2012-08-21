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
  # Convert \t characters to +n+ spaces (a number.)
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
    
    HTML_ESCAPE = {  #:nodoc:
      '&' => '&amp;',
      '"' => '&quot;',
      '>' => '&gt;',
      '<' => '&lt;',
    }
    
    # This was to prevent illegal HTML.
    # Strange chars should still be avoided in codes.
    evil_chars = Array(0x00...0x20) - [?\n, ?\t, ?\s]
    evil_chars.each { |i| HTML_ESCAPE[i.chr] = ' ' }
    #ansi_chars = Array(0x7f..0xff)
    #ansi_chars.each { |i| HTML_ESCAPE[i.chr] = '&#%d;' % i }
    # \x9 (\t) and \xA (\n) not included
    #HTML_ESCAPE_PATTERN = /[\t&"><\0-\x8\xB-\x1f\x7f-\xff]/
    HTML_ESCAPE_PATTERN = /[\t"&><\0-\x8\xB-\x1f]/
    
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
      
      if options[:wrap] || options[:line_numbers]
        @real_out = @out
        @out = ''
      end
      
      options[:break_lines] = true if options[:line_numbers] == :inline
      
      @break_lines = (options[:break_lines] == true)
      
      @HTML_ESCAPE = HTML_ESCAPE.dup
      @HTML_ESCAPE["\t"] = ' ' * options[:tab_width]
      
      @opened = []
      @last_opened = nil
      @css = CSS.new options[:style]
      
      hint = options[:hint]
      if hint && ![:debug, :info, :info_long].include?(hint)
        raise ArgumentError, "Unknown value %p for :hint; \
          expected :info, :info_long, :debug, false, or nil." % hint
      end
      
      css_classes = TokenKinds
      case options[:css]
      when :class
        @span_for_kind = Hash.new do |h, k|
          if k.is_a? ::Symbol
            kind = k_dup = k
          else
            kind = k.first
            k_dup = k.dup
          end
          if kind != :space && (hint || css_class = css_classes[kind])
            title = HTML.token_path_to_hint hint, k if hint
            css_class ||= css_classes[kind]
            h[k_dup] = "<span#{title}#{" class=\"#{css_class}\"" if css_class}>"
          else
            h[k_dup] = nil
          end
        end
      when :style
        @span_for_kind = Hash.new do |h, k|
          kind = k.is_a?(Symbol) ? k : k.first
          h[k.is_a?(Symbol) ? k : k.dup] =
            if kind != :space && (hint || css_classes[kind])
              title = HTML.token_path_to_hint hint, k if hint
              style = @css.get_style Array(k).map { |c| css_classes[c] }
              "<span#{title}#{" style=\"#{style}\"" if style}>"
            end
        end
      else
        raise ArgumentError, "Unknown value %p for :css." % options[:css]
      end
      
      @set_last_opened = options[:hint] || options[:css] == :style
    end
    
    def finish options
      unless @opened.empty?
        warn '%d tokens still open: %p' % [@opened.size, @opened] if $CODERAY_DEBUG
        @out << '</span>' while @opened.pop
        @last_opened = nil
      end
      
      @out.extend Output
      @out.css = @css
      if options[:line_numbers]
        Numbering.number! @out, options[:line_numbers], options
      end
      @out.wrap! options[:wrap]
      @out.apply_title! options[:title]
      
      if defined?(@real_out) && @real_out
        @real_out << @out
        @out = @real_out
      end
      
      super
    end
    
  public
    
    def text_token text, kind
      if text =~ /#{HTML_ESCAPE_PATTERN}/o
        text = text.gsub(/#{HTML_ESCAPE_PATTERN}/o) { |m| @HTML_ESCAPE[m] }
      end
      
      style = @span_for_kind[@last_opened ? [kind, *@opened] : kind]
      
      if @break_lines && (i = text.index("\n")) && (c = @opened.size + (style ? 1 : 0)) > 0
        close = '</span>' * c
        reopen = ''
        @opened.each_with_index do |k, index|
          reopen << (@span_for_kind[index > 0 ? [k, *@opened[0 ... index ]] : k] || '<span>')
        end
        text[i .. -1] = text[i .. -1].gsub("\n", "#{close}\n#{reopen}#{style}")
      end
      
      if style
        @out << style << text << '</span>'
      else
        @out << text
      end
    end
    
    # token groups, eg. strings
    def begin_group kind
      @out << (@span_for_kind[@last_opened ? [kind, *@opened] : kind] || '<span>')
      @opened << kind
      @last_opened = kind if @set_last_opened
    end
    
    def end_group kind
      if $CODERAY_DEBUG && (@opened.empty? || @opened.last != kind)
        warn 'Malformed token stream: Trying to close a token (%p) ' \
          'that is not open. Open are: %p.' % [kind, @opened[1..-1]]
      end
      if @opened.pop
        @out << '</span>'
        @last_opened = @opened.last if @last_opened
      end
    end
    
    # whole lines to be highlighted, eg. a deleted line in a diff
    def begin_line kind
      if style = @span_for_kind[@last_opened ? [kind, *@opened] : kind]
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
      if $CODERAY_DEBUG && (@opened.empty? || @opened.last != kind)
        warn 'Malformed token stream: Trying to close a line (%p) ' \
          'that is not open. Open are: %p.' % [kind, @opened[1..-1]]
      end
      if @opened.pop
        @out << '</span>'
        @last_opened = @opened.last if @last_opened
      end
    end
    
  end
  
end
end
