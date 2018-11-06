unless ("check partition".partition(" ") rescue false)
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class String
    def partition_with_new_meaning(pattern = Backports::Undefined)
      return partition_without_new_meaning{|c| yield c} if pattern == Backports::Undefined
      pattern = Backports.coerce_to(pattern, String, :to_str) unless pattern.is_a? Regexp
      i = index(pattern)
      return [self, "", ""] unless i
      if pattern.is_a? Regexp
        match = Regexp.last_match
        [match.pre_match, match[0], match.post_match]
      else
        last = i+pattern.length
        [self[0...i], self[i...last], self[last...length]]
      end
    end
    Backports.alias_method_chain self, :partition, :new_meaning
  end
end
