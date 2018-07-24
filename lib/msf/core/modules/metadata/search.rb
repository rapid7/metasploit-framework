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

    params = parse_search_string(search_string)

    get_metadata.each { |module_metadata|
      if is_match(params, module_metadata)
        search_results << module_metadata
      end
    }

    return search_results
  end

  # Helper method for private `is_match`
  def matches(params, module_metadata)
    is_match(params, module_metadata)
  end

  #######
  private
  #######

  def parse_search_string(search_string)
    # Split search terms by space, but allow quoted strings
    terms = search_string.split(/\"/).collect{|t| t.strip==t ? t : t.split(' ')}.flatten
    terms.delete('')

    # All terms are either included or excluded
    res = {}

    terms.each do |t|
      f,v = t.split(":", 2)
      unless v
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
    res
  end

  def is_match(params, module_metadata)
    return false if params.empty?

    k = params

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
            when 'app'
              match = [t,w] if (w == "server" and module_metadata.is_server)
              match = [t,w] if (w == "client" and module_metadata.is_client)
            when 'author', 'authors'
              match = [t,w] if module_metadata.author.any? { |a| a =~ r }
            when 'arch'
              match = [t,w,] if module_metadata.arch =~ r
            when 'cve'
              match = [t,w] if module_metadata.references.any? { |ref| ref =~ /^cve\-/i and ref =~ r }
            when 'bid'
              match = [t,w] if module_metadata.references.any? { |ref| ref =~ /^bid\-/i and ref =~ r }
            when 'edb'
              match = [t,w] if module_metadata.references.any? { |ref| ref =~ /^edb\-/i and ref =~ r }
            when 'date', 'disclosure_date'
              match = [t,w] if module_metadata.disclosure_date.to_s =~ r
            when 'description'
              match = [t,w] if module_metadata.description =~ r
            when 'full_name', 'fullname'
              match = [t,w] if module_metadata.full_name =~ r
            when 'mod_time'
              match = [t,w] if module_metadata.mod_time.to_s =~ r
            when 'name'
              match = [t,w] if module_metadata.name =~ r
            when 'os', 'platform'
              match = [t,w] if module_metadata.platform  =~ r or module_metadata.arch  =~ r
              if module_metadata.targets
                match = [t,w] if module_metadata.targets.any? { |t| t =~ r }
              end
            when 'path'
              match = [t,w] if module_metadata.full_name =~ r
            when 'port', 'rport'
              match = [t,w] if module_metadata.rport.to_s =~ r
            when 'rank'
              # Determine if param was prepended with gt, lt, gte, lte, or eq
              # Ex: "lte300" should match all ranks <= 300
              query_rank = w.dup
              operator = query_rank[0,3].tr('0-9', '')
              matches_rank = module_metadata.rank == w.to_i
              unless operator.empty?
                query_rank.slice! operator
                query_rank = query_rank.to_i
                case operator
                  when 'gt'
                    matches_rank = module_metadata.rank.to_i > query_rank
                  when 'lt'
                    matches_rank = module_metadata.rank.to_i < query_rank
                  when 'gte'
                    matches_rank = module_metadata.rank.to_i >= query_rank
                  when 'lte'
                    matches_rank = module_metadata.rank.to_i <= query_rank
                  when 'eq'
                    matches_rank = module_metadata.rank.to_i == query_rank
                end
              end
              match = [t,w] if matches_rank
            when 'ref', 'ref_name'
              match = [t,w] if module_metadata.ref_name =~ r
            when 'reference', 'references'
              match = [t,w] if module_metadata.references.any? { |ref| ref =~ r }
            when 'target', 'targets'
              match = [t,w] if module_metadata.targets.any? { |target| target =~ r }
            when 'text'
              terms = [module_metadata.name, module_metadata.full_name, module_metadata.description] + module_metadata.references + module_metadata.author

              if module_metadata.targets
                terms = terms + module_metadata.targets
              end
              match = [t,w] if terms.any? { |x| x =~ r }
            when 'type'
              match = [t,w] if Msf::MODULE_TYPES.any? { |modt| w == modt and module_metadata.type == modt }
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

