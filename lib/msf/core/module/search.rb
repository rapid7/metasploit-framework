module Msf::Module::Search
  #
  # This provides a standard set of search filters for every module.
  # The search terms are in the form of:
  #   {
  #     "text" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ],
  #     "cve" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ]
  #   }
  #
  # Returns true on no match, false on match
  #
  def search_filter(search_string)
    return false if not search_string

    search_string += " "

    # Split search terms by space, but allow quoted strings
    terms = search_string.split(/\"/).collect{|t| t.strip==t ? t : t.split(' ')}.flatten
    terms.delete('')

    # All terms are either included or excluded
    res = {}

    terms.each do |t|
      f,v = t.split(":", 2)
      if not v
        v = f
        f = 'text'
      end
      next if v.length == 0
      f.downcase!
      v.downcase!
      res[f] ||=[   [],    []   ]
      if v[0,1] == "-"
        next if v.length == 1
        res[f][1] << v[1,v.length-1]
      else
        res[f][0] << v
      end
    end

    k = res

    refs = self.references.map{|x| [x.ctx_id, x.ctx_val].join("-") }

    [0,1].each do |mode|
      match = false
      k.keys.each do |t|
        next if k[t][mode].length == 0

        k[t][mode].each do |w|
          # Reset the match flag for each keyword for inclusive search
          match = false if mode == 0

          # Convert into a case-insensitive regex
          r = Regexp.new(Regexp.escape(w), true)

          case t
            when 'text'
              terms = [self.name, self.fullname, self.description] + refs + self.author.map{|x| x.to_s}
              if self.respond_to?(:targets) and self.targets
                terms = terms + self.targets.map{|x| x.name}
              end
              match = [t,w] if terms.any? { |x| x =~ r }
            when 'name'
              match = [t,w] if self.name =~ r
            when 'path'
              match = [t,w] if self.fullname =~ r
            when 'author'
              match = [t,w] if self.author.map{|x| x.to_s}.any? { |a| a =~ r }
            when 'os', 'platform'
              match = [t,w] if self.platform_to_s =~ r or self.arch_to_s =~ r
              if not match and self.respond_to?(:targets) and self.targets
                match = [t,w] if self.targets.map{|x| x.name}.any? { |t| t =~ r }
              end
            when 'port'
              match = [t,w] if self.datastore['RPORT'].to_s =~ r
            when 'type'
              match = [t,w] if Msf::MODULE_TYPES.any? { |modt| w == modt and self.type == modt }
            when 'cve'
              match = [t,w] if refs.any? { |ref| ref =~ /^cve\-/i and ref =~ r }
            when 'bid'
              match = [t,w] if refs.any? { |ref| ref =~ /^bid\-/i and ref =~ r }
            when 'edb'
              match = [t,w] if refs.any? { |ref| ref =~ /^edb\-/i and ref =~ r }
          end
          break if match
        end
        # Filter this module if no matches for a given keyword type
        if mode == 0 and not match
          return true
        end
      end
      # Filter this module if we matched an exclusion keyword (-value)
      if mode == 1 and match
        return true
      end
    end

    false
  end
end
