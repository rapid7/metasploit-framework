module CodeRay
  
  # The Tokens class represents a list of tokens returned from
  # a Scanner. It's actually just an Array with a few helper methods.
  #
  # A token itself is not a special object, just two elements in an Array:
  # * the _token_ _text_ (the original source of the token in a String) or
  #   a _token_ _action_ (begin_group, end_group, begin_line, end_line)
  # * the _token_ _kind_ (a Symbol representing the type of the token)
  #
  # It looks like this:
  #
  #   ..., '# It looks like this', :comment, ...
  #   ..., '3.1415926', :float, ...
  #   ..., '$^', :error, ...
  #
  # Some scanners also yield sub-tokens, represented by special
  # token actions, for example :begin_group and :end_group.
  #
  # The Ruby scanner, for example, splits "a string" into:
  #
  #  [
  #   :begin_group, :string,
  #   '"',          :delimiter,
  #   'a string',   :content,
  #   '"',          :delimiter,
  #   :end_group,   :string
  #  ]
  #
  # Tokens can be used to save the output of a Scanners in a simple
  # Ruby object that can be send to an Encoder later:
  #
  #   tokens = CodeRay.scan('price = 2.59', :ruby).tokens
  #   tokens.encode(:html)
  #   tokens.html
  #   CodeRay.encoder(:html).encode_tokens(tokens)
  #
  # Tokens gives you the power to handle pre-scanned code very easily:
  # You can serialize it to a JSON string and store it in a database, pass it
  # around to encode it more than once, send it to other algorithms...
  class Tokens < Array
    
    # The Scanner instance that created the tokens.
    attr_accessor :scanner
    
    # Encode the tokens using encoder.
    #
    # encoder can be
    # * a plugin name like :html oder 'statistic'
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
      return Array.new(sizes.size) { Tokens.new } if size == 2 && first == ''
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
    
    # Return the actual number of tokens.
    def count
      size / 2
    end
    
    alias text_token push
    def begin_group kind; push :begin_group, kind end
    def end_group kind; push :end_group, kind end
    def begin_line kind; push :begin_line, kind end
    def end_line kind; push :end_line, kind end
    alias tokens concat
    
  end
  
end
