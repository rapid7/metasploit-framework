module CodeRay
  
  # The result of a scan operation is a TokensProxy, but should act like Tokens.
  # 
  # This proxy makes it possible to use the classic CodeRay.scan.encode API
  # while still providing the benefits of direct streaming.
  class TokensProxy
    
    attr_accessor :input, :lang, :options, :block
    
    # Create a new TokensProxy with the arguments of CodeRay.scan.
    def initialize input, lang, options = {}, block = nil
      @input   = input
      @lang    = lang
      @options = options
      @block   = block
    end
    
    # Call CodeRay.encode if +encoder+ is a Symbol;
    # otherwise, convert the receiver to tokens and call encoder.encode_tokens.
    def encode encoder, options = {}
      if encoder.respond_to? :to_sym
        CodeRay.encode(input, lang, encoder, options)
      else
        encoder.encode_tokens tokens, options
      end
    end
    
    # Tries to call encode;
    # delegates to tokens otherwise.
    def method_missing method, *args, &blk
      encode method.to_sym, *args
    rescue PluginHost::PluginNotFound
      tokens.send(method, *args, &blk)
    end
    
    # The (cached) result of the tokenized input; a Tokens instance.
    def tokens
      @tokens ||= scanner.tokenize(input)
    end
    
    # A (cached) scanner instance to use for the scan task.
    def scanner
      @scanner ||= CodeRay.scanner(lang, options, &block)
    end
    
    # Overwrite Struct#each.
    def each *args, &blk
      tokens.each(*args, &blk)
      self
    end
    
  end
  
end
