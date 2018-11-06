module CodeRay
module Encoders
  
  load :lint
  
  # = Debug Lint Encoder
  #
  # Debug encoder with additional checks for:
  # 
  # - empty tokens
  # - incorrect nesting
  # 
  # It will raise an InvalidTokenStream exception when any of the above occurs.
  # 
  # See also: Encoders::Debug
  class DebugLint < Debug
    
    register_for :debug_lint
    
    def text_token text, kind
      raise Lint::EmptyToken,       'empty token for %p' % [kind] if text.empty?
      raise Lint::UnknownTokenKind, 'unknown token kind %p (text was %p)' % [kind, text] unless TokenKinds.has_key? kind
      super
    end
    
    def begin_group kind
      @opened << kind
      super
    end
    
    def end_group kind
      raise Lint::IncorrectTokenGroupNesting, 'We are inside %s, not %p (end_group)' % [@opened.reverse.map(&:inspect).join(' < '), kind] if @opened.last != kind
      @opened.pop
      super
    end
    
    def begin_line kind
      @opened << kind
      super
    end
    
    def end_line kind
      raise Lint::IncorrectTokenGroupNesting, 'We are inside %s, not %p (end_line)' % [@opened.reverse.map(&:inspect).join(' < '), kind] if @opened.last != kind
      @opened.pop
      super
    end
    
    protected
    
    def setup options
      super
      @opened = []
    end
    
    def finish options
      raise 'Some tokens still open at end of token stream: %p' % [@opened] unless @opened.empty?
      super
    end
    
  end
  
end
end
