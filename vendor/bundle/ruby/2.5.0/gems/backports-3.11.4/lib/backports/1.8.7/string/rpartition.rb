unless String.method_defined? :rpartition
  require 'backports/tools/arguments'

  class String
    def rpartition(pattern)
      pattern = Backports.coerce_to(pattern, String, :to_str) unless pattern.is_a? Regexp
      i = rindex(pattern)
      return ["", "", self] unless i

      if pattern.is_a? Regexp
        match = Regexp.last_match
        [match.pre_match, match[0], match.post_match]
      else
        last = i+pattern.length
        [self[0...i], self[i...last], self[last...length]]
      end
    end
  end
end
