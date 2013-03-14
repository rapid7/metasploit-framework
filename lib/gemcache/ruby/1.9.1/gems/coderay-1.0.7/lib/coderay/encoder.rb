module CodeRay
  
  # This module holds the Encoder class and its subclasses.
  # For example, the HTML encoder is named CodeRay::Encoders::HTML
  # can be found in coderay/encoders/html.
  #
  # Encoders also provides methods and constants for the register
  # mechanism and the [] method that returns the Encoder class
  # belonging to the given format.
  module Encoders
    
    extend PluginHost
    plugin_path File.dirname(__FILE__), 'encoders'
    
    # = Encoder
    #
    # The Encoder base class. Together with Scanner and
    # Tokens, it forms the highlighting triad.
    #
    # Encoder instances take a Tokens object and do something with it.
    #
    # The most common Encoder is surely the HTML encoder
    # (CodeRay::Encoders::HTML). It highlights the code in a colorful
    # html page.
    # If you want the highlighted code in a div or a span instead,
    # use its subclasses Div and Span.
    class Encoder
      extend Plugin
      plugin_host Encoders
      
      class << self
        
        # If FILE_EXTENSION isn't defined, this method returns the
        # downcase class name instead.
        def const_missing sym
          if sym == :FILE_EXTENSION
            (defined?(@plugin_id) && @plugin_id || name[/\w+$/].downcase).to_s
          else
            super
          end
        end
        
        # The default file extension for output file of this encoder class.
        def file_extension
          self::FILE_EXTENSION
        end
        
      end
      
      # Subclasses are to store their default options in this constant.
      DEFAULT_OPTIONS = { }
      
      # The options you gave the Encoder at creating.
      attr_accessor :options, :scanner
      
      # Creates a new Encoder.
      # +options+ is saved and used for all encode operations, as long
      # as you don't overwrite it there by passing additional options.
      #
      # Encoder objects provide three encode methods:
      # - encode simply takes a +code+ string and a +lang+
      # - encode_tokens expects a +tokens+ object instead
      #
      # Each method has an optional +options+ parameter. These are
      # added to the options you passed at creation.
      def initialize options = {}
        @options = self.class::DEFAULT_OPTIONS.merge options
        @@CODERAY_TOKEN_INTERFACE_DEPRECATION_WARNING_GIVEN = false
      end
      
      # Encode a Tokens object.
      def encode_tokens tokens, options = {}
        options = @options.merge options
        @scanner = tokens.scanner if tokens.respond_to? :scanner
        setup options
        compile tokens, options
        finish options
      end
      
      # Encode the given +code+ using the Scanner for +lang+.
      def encode code, lang, options = {}
        options = @options.merge options
        @scanner = Scanners[lang].new code, CodeRay.get_scanner_options(options).update(:tokens => self)
        setup options
        @scanner.tokenize
        finish options
      end
      
      # You can use highlight instead of encode, if that seems
      # more clear to you.
      alias highlight encode
      
      # The default file extension for this encoder.
      def file_extension
        self.class.file_extension
      end
      
      def << token
        unless @@CODERAY_TOKEN_INTERFACE_DEPRECATION_WARNING_GIVEN
          warn 'Using old Tokens#<< interface.'
          @@CODERAY_TOKEN_INTERFACE_DEPRECATION_WARNING_GIVEN = true
        end
        self.token(*token)
      end
      
      # Called with +content+ and +kind+ of the currently scanned token.
      # For simple scanners, it's enougth to implement this method.
      #
      # By default, it calls text_token, begin_group, end_group, begin_line,
      # or end_line, depending on the +content+.
      def token content, kind
        case content
        when String
          text_token content, kind
        when :begin_group
          begin_group kind
        when :end_group
          end_group kind
        when :begin_line
          begin_line kind
        when :end_line
          end_line kind
        else
          raise ArgumentError, 'Unknown token content type: %p, kind = %p' % [content, kind]
        end
      end
      
      # Called for each text token ([text, kind]), where text is a String.
      def text_token text, kind
        @out << text
      end
      
      # Starts a token group with the given +kind+.
      def begin_group kind
      end
      
      # Ends a token group with the given +kind+.
      def end_group kind
      end
      
      # Starts a new line token group with the given +kind+.
      def begin_line kind
      end
      
      # Ends a new line token group with the given +kind+.
      def end_line kind
      end
      
    protected
      
      # Called with merged options before encoding starts.
      # Sets @out to an empty string.
      #
      # See the HTML Encoder for an example of option caching.
      def setup options
        @out = get_output(options)
      end
      
      def get_output options
        options[:out] || ''
      end
      
      # Append data.to_s to the output. Returns the argument.
      def output data
        @out << data.to_s
        data
      end
      
      # Called with merged options after encoding starts.
      # The return value is the result of encoding, typically @out.
      def finish options
        @out
      end
      
      # Do the encoding.
      #
      # The already created +tokens+ object must be used; it must be a
      # Tokens object.
      def compile tokens, options = {}
        content = nil
        for item in tokens
          if item.is_a? Array
            raise ArgumentError, 'Two-element array tokens are no longer supported.'
          end
          if content
            token content, item
            content = nil
          else
            content = item
          end
        end
        raise 'odd number list for Tokens' if content
      end
      
      alias tokens compile
      public :tokens
      
    end
    
  end
end
