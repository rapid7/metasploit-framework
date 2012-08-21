# encoding: utf-8
require 'strscan'

module CodeRay
  
  autoload :WordList, coderay_path('helpers', 'word_list')
  
  # = Scanners
  #
  # This module holds the Scanner class and its subclasses.
  # For example, the Ruby scanner is named CodeRay::Scanners::Ruby
  # can be found in coderay/scanners/ruby.
  #
  # Scanner also provides methods and constants for the register
  # mechanism and the [] method that returns the Scanner class
  # belonging to the given lang.
  #
  # See PluginHost.
  module Scanners
    extend PluginHost
    plugin_path File.dirname(__FILE__), 'scanners'
    
    
    # = Scanner
    #
    # The base class for all Scanners.
    #
    # It is a subclass of Ruby's great +StringScanner+, which
    # makes it easy to access the scanning methods inside.
    #
    # It is also +Enumerable+, so you can use it like an Array of
    # Tokens:
    #
    #   require 'coderay'
    #   
    #   c_scanner = CodeRay::Scanners[:c].new "if (*p == '{') nest++;"
    #   
    #   for text, kind in c_scanner
    #     puts text if kind == :operator
    #   end
    #   
    #   # prints: (*==)++;
    #
    # OK, this is a very simple example :)
    # You can also use +map+, +any?+, +find+ and even +sort_by+,
    # if you want.
    class Scanner < StringScanner
      
      extend Plugin
      plugin_host Scanners
      
      # Raised if a Scanner fails while scanning
      ScanError = Class.new StandardError
      
      # The default options for all scanner classes.
      #
      # Define @default_options for subclasses.
      DEFAULT_OPTIONS = { }
      
      KINDS_NOT_LOC = [:comment, :doctype, :docstring]
      
      attr_accessor :state
      
      class << self
        
        # Normalizes the given code into a string with UNIX newlines, in the
        # scanner's internal encoding, with invalid and undefined charachters
        # replaced by placeholders. Always returns a new object.
        def normalize code
          # original = code
          code = code.to_s unless code.is_a? ::String
          return code if code.empty?
          
          if code.respond_to? :encoding
            code = encode_with_encoding code, self.encoding
          else
            code = to_unix code
          end
          # code = code.dup if code.eql? original
          code
        end
        
        # The typical filename suffix for this scanner's language.
        def file_extension extension = lang
          @file_extension ||= extension.to_s
        end
        
        # The encoding used internally by this scanner.
        def encoding name = 'UTF-8'
          @encoding ||= defined?(Encoding.find) && Encoding.find(name)
        end
        
        # The lang of this Scanner class, which is equal to its Plugin ID.
        def lang
          @plugin_id
        end
        
      protected
        
        def encode_with_encoding code, target_encoding
          if code.encoding == target_encoding
            if code.valid_encoding?
              return to_unix(code)
            else
              source_encoding = guess_encoding code
            end
          else
            source_encoding = code.encoding
          end
          # print "encode_with_encoding from #{source_encoding} to #{target_encoding}"
          code.encode target_encoding, source_encoding, :universal_newline => true, :undef => :replace, :invalid => :replace
        end
        
        def to_unix code
          code.index(?\r) ? code.gsub(/\r\n?/, "\n") : code
        end
        
        def guess_encoding s
          #:nocov:
          IO.popen("file -b --mime -", "w+") do |file|
            file.write s[0, 1024]
            file.close_write
            begin
              Encoding.find file.gets[/charset=([-\w]+)/, 1]
            rescue ArgumentError
              Encoding::BINARY
            end
          end
          #:nocov:
        end
        
      end
      
      # Create a new Scanner.
      #
      # * +code+ is the input String and is handled by the superclass
      #   StringScanner.
      # * +options+ is a Hash with Symbols as keys.
      #   It is merged with the default options of the class (you can
      #   overwrite default options here.)
      #
      # Else, a Tokens object is used.
      def initialize code = '', options = {}
        if self.class == Scanner
          raise NotImplementedError, "I am only the basic Scanner class. I can't scan anything. :( Use my subclasses."
        end
        
        @options = self.class::DEFAULT_OPTIONS.merge options
        
        super self.class.normalize(code)
        
        @tokens = options[:tokens] || Tokens.new
        @tokens.scanner = self if @tokens.respond_to? :scanner=
        
        setup
      end
      
      # Sets back the scanner. Subclasses should redefine the reset_instance
      # method instead of this one.
      def reset
        super
        reset_instance
      end
      
      # Set a new string to be scanned.
      def string= code
        code = self.class.normalize(code)
        super code
        reset_instance
      end
      
      # the Plugin ID for this scanner
      def lang
        self.class.lang
      end
      
      # the default file extension for this scanner
      def file_extension
        self.class.file_extension
      end
      
      # Scan the code and returns all tokens in a Tokens object.
      def tokenize source = nil, options = {}
        options = @options.merge(options)
        @tokens = options[:tokens] || @tokens || Tokens.new
        @tokens.scanner = self if @tokens.respond_to? :scanner=
        case source
        when Array
          self.string = self.class.normalize(source.join)
        when nil
          reset
        else
          self.string = self.class.normalize(source)
        end
        
        begin
          scan_tokens @tokens, options
        rescue => e
          message = "Error in %s#scan_tokens, initial state was: %p" % [self.class, defined?(state) && state]
          raise_inspect e.message, @tokens, message, 30, e.backtrace
        end
        
        @cached_tokens = @tokens
        if source.is_a? Array
          @tokens.split_into_parts(*source.map { |part| part.size })
        else
          @tokens
        end
      end
      
      # Cache the result of tokenize.
      def tokens
        @cached_tokens ||= tokenize
      end
      
      # Traverse the tokens.
      def each &block
        tokens.each(&block)
      end
      include Enumerable
      
      # The current line position of the scanner, starting with 1.
      # See also: #column.
      #
      # Beware, this is implemented inefficiently. It should be used
      # for debugging only.
      def line pos = self.pos
        return 1 if pos <= 0
        binary_string[0...pos].count("\n") + 1
      end
      
      # The current column position of the scanner, starting with 1.
      # See also: #line.
      def column pos = self.pos
        return 1 if pos <= 0
        pos - (binary_string.rindex(?\n, pos - 1) || -1)
      end
      
      # The string in binary encoding.
      # 
      # To be used with #pos, which is the index of the byte the scanner
      # will scan next.
      def binary_string
        @binary_string ||=
          if string.respond_to?(:bytesize) && string.bytesize != string.size
            #:nocov:
            string.dup.force_encoding('binary')
            #:nocov:
          else
            string
          end
      end
      
    protected
      
      # Can be implemented by subclasses to do some initialization
      # that has to be done once per instance.
      #
      # Use reset for initialization that has to be done once per
      # scan.
      def setup  # :doc:
      end
      
      # This is the central method, and commonly the only one a
      # subclass implements.
      #
      # Subclasses must implement this method; it must return +tokens+
      # and must only use Tokens#<< for storing scanned tokens!
      def scan_tokens tokens, options  # :doc:
        raise NotImplementedError, "#{self.class}#scan_tokens not implemented."
      end
      
      # Resets the scanner.
      def reset_instance
        @tokens.clear if @tokens.respond_to?(:clear) && !@options[:keep_tokens]
        @cached_tokens = nil
        @binary_string = nil if defined? @binary_string
      end
      
      # Scanner error with additional status information
      def raise_inspect msg, tokens, state = self.state || 'No state given!', ambit = 30, backtrace = caller
        raise ScanError, <<-EOE % [


***ERROR in %s: %s (after %d tokens)

tokens:
%s

current line: %d  column: %d  pos: %d
matched: %p  state: %p
bol? = %p,  eos? = %p

surrounding code:
%p  ~~  %p


***ERROR***

        EOE
          File.basename(caller[0]),
          msg,
          tokens.respond_to?(:size) ? tokens.size : 0,
          tokens.respond_to?(:last) ? tokens.last(10).map { |t| t.inspect }.join("\n") : '',
          line, column, pos,
          matched, state, bol?, eos?,
          binary_string[pos - ambit, ambit],
          binary_string[pos, ambit],
        ], backtrace
      end
      
      # Shorthand for scan_until(/\z/).
      # This method also avoids a JRuby 1.9 mode bug.
      def scan_rest
        rest = self.rest
        terminate
        rest
      end
      
    end
    
  end
end
