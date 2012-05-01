module Liquid

  class Tag

    attr_accessor :nodelist

    def initialize(tag_name, markup, tokens)
      @tag_name   = tag_name
      @markup     = markup
      parse(tokens)
    end

    def parse(tokens)
    end

    def name
      self.class.name.downcase
    end

    def render(context)
      ''
    end

  end # Tag

end # Tag
