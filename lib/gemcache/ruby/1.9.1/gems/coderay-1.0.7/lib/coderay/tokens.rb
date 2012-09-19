module CodeRay
  
  # GZip library for writing and reading token dumps.
  autoload :GZip, coderay_path('helpers', 'gzip')
  
  # = Tokens  TODO: Rewrite!
  #
  # The Tokens class represents a list of tokens returnd from
  # a Scanner.
  #
  # A token is not a special object, just a two-element Array
  # consisting of
  # * the _token_ _text_ (the original source of the token in a String) or
  #   a _token_ _action_ (begin_group, end_group, begin_line, end_line)
  # * the _token_ _kind_ (a Symbol representing the type of the token)
  #
  # A token looks like this:
  #
  #   ['# It looks like this', :comment]
  #   ['3.1415926', :float]
  #   ['$^', :error]
  #
  # Some scanners also yield sub-tokens, represented by special
  # token actions, namely begin_group and end_group.
  #
  # The Ruby scanner, for example, splits "a string" into:
  #
  #  [
  #   [:begin_group, :string],
  #   ['"', :delimiter],
  #   ['a string', :content],
  #   ['"', :delimiter],
  #   [:end_group, :string]
  #  ]
  #
  # Tokens is the interface between Scanners and Encoders:
  # The input is split and saved into a Tokens object. The Encoder
  # then builds the output from this object.
  #
  # Thus, the syntax below becomes clear:
  #
  #   CodeRay.scan('price = 2.59', :ruby).html
  #   # the Tokens object is here -------^
  #
  # See how small it is? ;)
  #
  # Tokens gives you the power to handle pre-scanned code very easily:
  # You can convert it to a webpage, a YAML file, or dump it into a gzip'ed string
  # that you put in your DB.
  # 
  # It also allows you to generate tokens directly (without using a scanner),
  # to load them from a file, and still use any Encoder that CodeRay provides.
  class Tokens < Array
    
    # The Scanner instance that created the tokens.
    attr_accessor :scanner
    
    # Encode the tokens using encoder.
    #
    # encoder can be
    # * a symbol like :html oder :statistic
    # * an Encoder class
    # * an Encoder object
    #
    # options are passed to the encoder.
    def encode encoder, options = {}
      encoder = Encoders[encoder].new options if encoder.respond_to? :to_sym
      encoder.encode_tokens self, options
    end
    
    # Turn tokens into a string by concatenating them.
    def to_s
      encode CodeRay::Encoders::Encoder.new
    end
    
    # Redirects unknown methods to encoder calls.
    #
    # For example, if you call +tokens.html+, the HTML encoder
    # is used to highlight the tokens.
    def method_missing meth, options = {}
      encode meth, options
    rescue PluginHost::PluginNotFound
      super
    end
    
    # Split the tokens into parts of the given +sizes+.
    # 
    # The result will be an Array of Tokens objects. The parts have
    # the text size specified by the parameter. In addition, each
    # part closes all opened tokens. This is useful to insert tokens
    # betweem them.
    # 
    # This method is used by @Scanner#tokenize@ when called with an Array
    # of source strings. The Diff encoder uses it for inline highlighting.
    def split_into_parts *sizes
      parts = []
      opened = []
      content = nil
      part = Tokens.new
      part_size = 0
      size = sizes.first
      i = 0
      for item in self
        case content
        when nil
          content = item
        when String
          if size && part_size + content.size > size  # token must be cut
            if part_size < size  # some part of the token goes into this part
              content = content.dup  # content may no be safe to change
              part << content.slice!(0, size - part_size) << item
            end
            # close all open groups and lines...
            closing = opened.reverse.flatten.map do |content_or_kind|
              case content_or_kind
              when :begin_group
                :end_group
              when :begin_line
                :end_line
              else
                content_or_kind
              end
            end
            part.concat closing
            begin
              parts << part
              part = Tokens.new
              size = sizes[i += 1]
            end until size.nil? || size > 0
            # ...and open them again.
            part.concat opened.flatten
            part_size = 0
            redo unless content.empty?
          else
            part << content << item
            part_size += content.size
          end
          content = nil
        when Symbol
          case content
          when :begin_group, :begin_line
            opened << [content, item]
          when :end_group, :end_line
            opened.pop
          else
            raise ArgumentError, 'Unknown token action: %p, kind = %p' % [content, item]
          end
          part << content << item
          content = nil
        else
          raise ArgumentError, 'Token input junk: %p, kind = %p' % [content, item]
        end
      end
      parts << part
      parts << Tokens.new while parts.size < sizes.size
      parts
    end
    
    # Dumps the object into a String that can be saved
    # in files or databases.
    #
    # The dump is created with Marshal.dump;
    # In addition, it is gzipped using GZip.gzip.
    #
    # The returned String object includes Undumping
    # so it has an #undump method. See Tokens.load.
    #
    # You can configure the level of compression,
    # but the default value 7 should be what you want
    # in most cases as it is a good compromise between
    # speed and compression rate.
    #
    # See GZip module.
    def dump gzip_level = 7
      dump = Marshal.dump self
      dump = GZip.gzip dump, gzip_level
      dump.extend Undumping
    end
    
    # Return the actual number of tokens.
    def count
      size / 2
    end
    
    # Include this module to give an object an #undump
    # method.
    #
    # The string returned by Tokens.dump includes Undumping.
    module Undumping
      # Calls Tokens.load with itself.
      def undump
        Tokens.load self
      end
    end
    
    # Undump the object using Marshal.load, then
    # unzip it using GZip.gunzip.
    #
    # The result is commonly a Tokens object, but
    # this is not guaranteed.
    def Tokens.load dump
      dump = GZip.gunzip dump
      @dump = Marshal.load dump
    end
    
    alias text_token push
    def begin_group kind; push :begin_group, kind end
    def end_group kind; push :end_group, kind end
    def begin_line kind; push :begin_line, kind end
    def end_line kind; push :end_line, kind end
    alias tokens concat
    
  end
  
end
