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
    terms = search_string.split(/\"/).collect{|term| term.strip==term ? term : term.split(' ')}.flatten
    terms.delete('')

    # All terms are either included or excluded
    res = {}

    terms.each do |term|
      keyword, search_term = term.split(":", 2)
      unless search_term
        search_term = keyword
        keyword = 'text'
      end
      next if search_term.length == 0
      keyword.downcase!
      search_term.downcase!
      res[keyword] ||=[   [],    []   ]
      if search_term[0,1] == "-"
        next if search_term.length == 1
        res[keyword][1] << search_term[1,search_term.length-1]
      else
        res[keyword][0] << search_term
      end
    end
    res
  end

  def is_match(params, module_metadata)
    return false if params.empty?

    param_hash = params

    [0,1].each do |mode|
      match = false
      param_hash.keys.each do |keyword|
        next if param_hash[keyword][mode].length == 0

        param_hash[keyword][mode].each do |search_term|
          # Reset the match flag for each keyword for inclusive search
          match = false if mode == 0

          # Convert into a case-insensitive regex
          regex = Regexp.new(Regexp.escape(search_term), true)

          case keyword
            when 'app'
              match = [keyword, search_term] if (search_term == "server" and module_metadata.is_server)
              match = [keyword, search_term] if (search_term == "client" and module_metadata.is_client)
            when 'author', 'authors'
              match = [keyword, search_term] if module_metadata.author.any? { |author| author =~ regex }
            when 'arch'
              match = [keyword, search_term,] if module_metadata.arch =~ regex
            when 'cve'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ /^cve\-/i and ref =~ regex }
            when 'bid'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ /^bid\-/i and ref =~ regex }
            when 'edb'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ /^edb\-/i and ref =~ regex }
            when 'date', 'disclosure_date'
              match = [keyword, search_term] if module_metadata.disclosure_date.to_s =~ regex
            when 'description'
              match = [keyword, search_term] if module_metadata.description =~ regex
            when 'full_name', 'fullname'
              match = [keyword, search_term] if module_metadata.full_name =~ regex
            when 'mod_time'
              match = [keyword, search_term] if module_metadata.mod_time.to_s =~ regex
            when 'name'
              match = [keyword, search_term] if module_metadata.name =~ regex
            when 'os', 'platform'
              match = [keyword, search_term] if module_metadata.platform  =~ regex or module_metadata.arch  =~ regex
              if module_metadata.targets
                match = [keyword, search_term] if module_metadata.targets.any? { |target| target =~ regex }
              end
            when 'path'
              match = [keyword, search_term] if module_metadata.full_name =~ regex
            when 'port', 'rport'
              match = [keyword, search_term] if module_metadata.rport.to_s =~ regex
            when 'rank'
              # Determine if param was prepended with gt, lt, gte, lte, or eq
              # Ex: "lte300" should match all ranks <= 300
              query_rank = search_term.dup
              operator = query_rank[0,3].tr('0-9', '')
              valid_operators = %w[eq gt lt gte lte]
              matches_rank = module_metadata.rank == search_term.to_i
              if valid_operators.include? operator
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
              else
                case query_rank
                when 'manual'
                  matches_rank = module_metadata.rank.to_i == Msf::ManualRanking
                when 'low'
                  matches_rank = module_metadata.rank.to_i == Msf::LowRanking
                when 'average'
                  matches_rank = module_metadata.rank.to_i == Msf::AverageRanking
                when 'normal'
                  matches_rank = module_metadata.rank.to_i == Msf::NormalRanking
                when 'good'
                  matches_rank = module_metadata.rank.to_i == Msf::GoodRanking
                when 'great'
                  matches_rank = module_metadata.rank.to_i == Msf::GreatRanking
                when 'excellent'
                  matches_rank = module_metadata.rank.to_i == Msf::ExcellentRanking
                end
              end
              match = [keyword, search_term] if matches_rank
            when 'ref', 'ref_name'
              match = [keyword, search_term] if module_metadata.ref_name =~ regex
            when 'reference', 'references'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ regex }
            when 'target', 'targets'
              match = [keyword, search_term] if module_metadata.targets.any? { |target| target =~ regex }
            when 'text'
              terms = [module_metadata.name, module_metadata.full_name, module_metadata.description] + module_metadata.references + module_metadata.author

              if module_metadata.targets
                terms = terms + module_metadata.targets
              end
              match = [keyword, search_term] if terms.any? { |term| term =~ regex }
            when 'type'
              match = [keyword, search_term] if Msf::MODULE_TYPES.any? { |module_type| search_term == module_type and module_metadata.type == module_type }
          else
              # Ignore extraneous/invalid keywords
              match = [keyword, search_term]
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

