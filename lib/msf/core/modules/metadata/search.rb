require 'msf/core/modules/metadata'

#
# Provides search operations on the module metadata cache.
#
module Msf::Modules::Metadata::Search
  #
  # Searches the module metadata using the passed search string.
  #
  def find(search_string)
    search_results = []

    get_metadata.each { |module_metadata|
      if is_match(search_string, module_metadata)
        search_results << module_metadata
      end
    }

    return search_results
  end

  #######
  private
  #######

  def is_match(search_string, module_metadata)
    return false if not search_string

    search_string += ' '

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
              terms = [module_metadata.name, module_metadata.full_name, module_metadata.description] + module_metadata.references + module_metadata.author

              if module_metadata.targets
                terms = terms + module_metadata.targets
              end
              match = [t,w] if terms.any? { |x| x =~ r }
            when 'name'
              match = [t,w] if module_metadata.name =~ r
            when 'path'
              match = [t,w] if module_metadata.full_name =~ r
            when 'author'
              match = [t,w] if module_metadata.author.any? { |a| a =~ r }
            when 'os', 'platform'
              match = [t,w] if module_metadata.platform  =~ r or module_metadata.arch  =~ r

              if module_metadata.targets
                match = [t,w] if module_metadata.targets.any? { |t| t =~ r }
              end
            when 'port'
              match = [t,w] if module_metadata.rport =~ r
            when 'type'
              match = [t,w] if Msf::MODULE_TYPES.any? { |modt| w == modt and module_metadata.type == modt }
            when 'app'
              match = [t,w] if (w == "server" and module_metadata.is_server)
              match = [t,w] if (w == "client" and module_metadata.is_client)
            when 'cve'
              match = [t,w] if module_metadata.references.any? { |ref| ref =~ /^cve\-/i and ref =~ r }
            when 'bid'
              match = [t,w] if module_metadata.references.any? { |ref| ref =~ /^bid\-/i and ref =~ r }
            when 'edb'
              match = [t,w] if module_metadata.references.any? { |ref| ref =~ /^edb\-/i and ref =~ r }
          end
          break if match
        end
        # Filter this module if no matches for a given keyword type
        if mode == 0 and not match
          return false
        end
      end
      # Filter this module if we matched an exclusion keyword (-value)
      if mode == 1 and match
        return false
      end
    end

    true
  end
end

