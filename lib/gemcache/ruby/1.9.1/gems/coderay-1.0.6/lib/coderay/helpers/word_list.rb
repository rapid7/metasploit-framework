module CodeRay
  
  # = WordList
  # 
  # <b>A Hash subclass designed for mapping word lists to token types.</b>
  # 
  # Copyright (c) 2006-2011 by murphy (Kornelius Kalnbach) <murphy rubychan de>
  #
  # License:: LGPL / ask the author
  # Version:: 2.0 (2011-05-08)
  #
  # A WordList is a Hash with some additional features.
  # It is intended to be used for keyword recognition.
  #
  # WordList is optimized to be used in Scanners,
  # typically to decide whether a given ident is a special token.
  #
  # For case insensitive words use WordList::CaseIgnoring.
  #
  # Example:
  #
  #  # define word arrays
  #  RESERVED_WORDS = %w[
  #    asm break case continue default do else
  #  ]
  #  
  #  PREDEFINED_TYPES = %w[
  #    int long short char void
  #  ]
  #  
  #  # make a WordList
  #  IDENT_KIND = WordList.new(:ident).
  #    add(RESERVED_WORDS, :reserved).
  #    add(PREDEFINED_TYPES, :predefined_type)
  #  
  #  ...
  #  
  #  def scan_tokens tokens, options
  #    ...
  #    
  #    elsif scan(/[A-Za-z_][A-Za-z_0-9]*/)
  #      # use it
  #      kind = IDENT_KIND[match]
  #      ...
  class WordList < Hash
    
    # Create a new WordList with +default+ as default value.
    def initialize default = false
      super default
    end
    
    # Add words to the list and associate them with +value+.
    # 
    # Returns +self+, so you can concat add calls.
    def add words, value = true
      words.each { |word| self[word] = value }
      self
    end
    
  end
  
  
  # A CaseIgnoring WordList is like a WordList, only that
  # keys are compared case-insensitively (normalizing keys using +downcase+).
  class WordList::CaseIgnoring < WordList
    
    def [] key
      super key.downcase
    end
    
    def []= key, value
      super key.downcase, value
    end
    
  end
  
end
