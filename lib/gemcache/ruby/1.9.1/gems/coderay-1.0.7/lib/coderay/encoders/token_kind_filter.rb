module CodeRay
module Encoders
  
  load :filter
  
  # A Filter that selects tokens based on their token kind.
  # 
  # == Options
  # 
  # === :exclude
  # 
  # One or many symbols (in an Array) which shall be excluded.
  # 
  # Default: []
  # 
  # === :include
  # 
  # One or many symbols (in an array) which shall be included.
  # 
  # Default: :all, which means all tokens are included.
  # 
  # Exclusion wins over inclusion.
  # 
  # See also: CommentFilter
  class TokenKindFilter < Filter
    
    register_for :token_kind_filter
    
    DEFAULT_OPTIONS = {
      :exclude => [],
      :include => :all
    }
    
  protected
    def setup options
      super
      
      @group_excluded = false
      @exclude = options[:exclude]
      @exclude = Array(@exclude) unless @exclude == :all
      @include = options[:include]
      @include = Array(@include) unless @include == :all
    end
    
    def include_text_token? text, kind
      include_group? kind
    end
    
    def include_group? kind
       (@include == :all || @include.include?(kind)) &&
      !(@exclude == :all || @exclude.include?(kind))
    end
    
  public
    
    # Add the token to the output stream if +kind+ matches the conditions.
    def text_token text, kind
      super if !@group_excluded && include_text_token?(text, kind)
    end
    
    # Add the token group to the output stream if +kind+ matches the
    # conditions.
    # 
    # If it does not, all tokens inside the group are excluded from the
    # stream, even if their kinds match.
    def begin_group kind
      if @group_excluded
        @group_excluded += 1
      elsif include_group? kind
        super
      else
        @group_excluded = 1
      end
    end
    
    # See +begin_group+.
    def begin_line kind
      if @group_excluded
        @group_excluded += 1
      elsif include_group? kind
        super
      else
        @group_excluded = 1
      end
    end
    
    # Take care of re-enabling the delegation of tokens to the output stream
    # if an exluded group has ended.
    def end_group kind
      if @group_excluded
        @group_excluded -= 1
        @group_excluded = false if @group_excluded.zero?
      else
        super
      end
    end
    
    # See +end_group+.
    def end_line kind
      if @group_excluded
        @group_excluded -= 1
        @group_excluded = false if @group_excluded.zero?
      else
        super
      end
    end
    
  end
  
end
end
