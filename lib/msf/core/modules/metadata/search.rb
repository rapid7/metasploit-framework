require 'msf/core/modules/metadata'

#
# Provides search operations on the module metadata cache.
#
module Msf::Modules::Metadata::Search

  VALID_PARAMS =
      %w[aka author authors arch cve bid edb check date disclosure_date description full_name fullname mod_time
      name os platform path port rport rank ref ref_name reference references target targets text type]

  #
  # Searches the module metadata using the passed hash of search params
  #
  def find(params, fields={})
    raise ArgumentError if params.empty? || VALID_PARAMS.none? { |k| params.key?(k) }
    search_results = []

    get_metadata.each { |module_metadata|
      if is_match(params, module_metadata)
        unless fields.empty?
          module_metadata = get_fields(module_metadata, fields)
        end
        search_results << module_metadata
      end
    }
    return search_results
  end

  #######
  private
  #######

  def is_match(params, module_metadata)
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
            when 'aka'
              match = [keyword, search_term] if (module_metadata.notes['AKA'] || []).any? { |aka| aka =~ regex }
            when 'author', 'authors'
              match = [keyword, search_term] if module_metadata.author.any? { |author| author =~ regex }
            when 'arch'
              match = [keyword, search_term] if module_metadata.arch =~ regex
            when 'cve'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ /^cve\-/i and ref =~ regex }
            when 'bid'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ /^bid\-/i and ref =~ regex }
            when 'edb'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ /^edb\-/i and ref =~ regex }
            when 'check'
              if module_metadata.check
                matches_check = %w(true yes).any? { |val| val =~ regex}
              else
                matches_check = %w(false no).any? { |val| val =~ regex}
              end
              match = [keyword, search_term] if matches_check
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
              elsif query_rank =~ /^\d+$/
                matches_rank = module_metadata.rank.to_i == query_rank.to_i
              else
                matches_rank = module_metadata.rank.to_i == Msf::RankingName.key(query_rank)
              end
              match = [keyword, search_term] if matches_rank
            when 'ref', 'ref_name'
              match = [keyword, search_term] if module_metadata.ref_name =~ regex
            when 'reference', 'references'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref =~ regex }
            when 'target', 'targets'
              match = [keyword, search_term] if module_metadata.targets.any? { |target| target =~ regex }
            when 'text'
              terms = [module_metadata.name, module_metadata.full_name, module_metadata.description] + module_metadata.references + module_metadata.author + (module_metadata.notes['AKA'] || [])

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

  def get_fields(module_metadata, fields)
    selected_fields = {}

    aliases = {
        :cve => 'references',
        :edb => 'references',
        :bid => 'references',
        :fullname => 'full_name',
        :os => 'platform',
        :port => 'rport',
        :reference => 'references',
        :ref => 'ref_name',
        :target => 'targets',
        :authors => 'author'
    }

    fields.each do | field |
      field = aliases[field.to_sym] if aliases[field.to_sym]
      if module_metadata.respond_to?(field)
        selected_fields[field] = module_metadata.send(field)
      end
    end
    selected_fields

  end

end

