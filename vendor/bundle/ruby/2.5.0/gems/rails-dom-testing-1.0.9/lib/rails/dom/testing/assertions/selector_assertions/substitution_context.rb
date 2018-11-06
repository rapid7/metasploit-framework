class SubstitutionContext
  def initialize
    @substitute = '?'
  end

  def substitute!(selector, values)
    while !values.empty? && substitutable?(values.first) && selector.index(@substitute)
      selector.sub! @substitute, matcher_for(values.shift)
    end
  end

  def match(matches, attribute, matcher)
    matches.find_all { |node| node[attribute] =~ Regexp.new(matcher) }
  end

  private
    def matcher_for(value)
      value.to_s.inspect # Nokogiri doesn't like arbitrary values without quotes, hence inspect.
    end

    def substitutable?(value)
      value.is_a?(String) || value.is_a?(Regexp)
    end
end
