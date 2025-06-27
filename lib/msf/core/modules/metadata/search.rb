# -*- coding: binary -*-


#
# Provides search operations on the module metadata cache.
#
module Msf::Modules::Metadata::Search

  VALID_PARAMS =
    %w[
      action
      adapter
      aka
      arch
      attack
      att&ck
      author
      authors
      bid
      check
      cve
      date
      description
      disclosure_date
      edb
      fullname
      mod_time
      name
      os
      osvdb
      path
      platform
      port
      rank
      ref
      ref_name
      reference
      references
      rport
      session_type
      stage
      stager
      target
      targets
      text
      type
    ]

  #
  # Module Type Shorthands
  #
  MODULE_TYPE_SHORTHANDS = {
    "aux" => Msf::MODULE_AUX
  }

  module SearchMode
    INCLUDE = 0
    EXCLUDE = 1
  end

  #
  # Parses command line search string into a hash. A param prefixed with '-' indicates "not", and will omit results
  # matching that keyword. This hash can be used with the find command.
  #
  # Resulting Hash Example:
  # {"platform"=>[["android"], []]} will match modules targeting the android platform
  # {"platform"=>[[], ["android"]]} will exclude modules targeting the android platform
  #
  def self.parse_search_string(search_string)
    search_string ||= ''
    search_string += ' '

    # Split search terms by space, but allow quoted strings
    terms = search_string.split('"').collect{|term| term.strip==term ? term : term.split(' ')}.flatten
    terms.delete('')

    # All terms are either included or excluded
    res = {}

    terms.each do |term|
      # Split it on the `:`, with the part before the first `:` going into keyword, the part after first `:`
      # but before any later instances of `:` going into search_term, and the characters after the second
      # `:` or later in the string going into _excess to be ignored.
      #
      # Example is `use exploit/linux/local/nested_namespace_idmap_limit_priv_esc::a`
      # which would make keyword become `exploit/linux/local/nested_namespace_idmap_limit_priv_esc`,
      # search_term become blank, and _excess become "a".
      keyword, search_term, _excess = term.split(":", 3)
      if search_term.blank?
        search_term = keyword
        keyword = 'text'
      end
      next if search_term.length == 0
      keyword.downcase!
      search_term.downcase!

      if keyword == "type"
        search_term = MODULE_TYPE_SHORTHANDS[search_term] if MODULE_TYPE_SHORTHANDS.key?(search_term)
      end

      res[keyword] ||=[   [],    []   ]
      if search_term[0,1] == "-"
        next if search_term.length == 1
        res[keyword][SearchMode::EXCLUDE] << search_term[1,search_term.length-1]
      else
        res[keyword][SearchMode::INCLUDE] << search_term
      end
    end
    res
  end

  #
  # Searches the module metadata using the passed hash of search params
  #
  def find(params, fields={})
    raise ArgumentError if params.any? && VALID_PARAMS.none? { |k| params.key?(k) }
    search_results = []

    regex_cache = Hash.new do |hash, search_term|
      hash[search_term] = as_regex(search_term)
    end
    get_metadata.each { |module_metadata|
      if is_match(params, module_metadata, regex_cache)
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

  def is_match(params, module_metadata, regex_cache)
    return true if params.empty?

    param_hash = params

    [SearchMode::INCLUDE, SearchMode::EXCLUDE].each do |mode|
      match = false
      param_hash.keys.each do |keyword|
        next if param_hash[keyword][mode].length == 0

        # free form text search will honor 'and' semantics, i.e. 'metasploit pro' will only match modules that contain both
        # words, and will return false when only one word is matched
        if keyword == 'text'
          module_actions = (module_metadata.actions || []).flat_map { |action| action.values.map(&:to_s) }
          text_segments = [module_metadata.name, module_metadata.fullname, module_metadata.description] + module_metadata.references + module_metadata.author + (module_metadata.notes['AKA'] || []) + module_actions

          if module_metadata.targets
            text_segments = text_segments + module_metadata.targets
          end

          param_hash[keyword][mode].each do |search_term|
            has_match = text_segments.any? { |text_segment| text_segment =~ regex_cache[search_term] }
            match = [keyword, search_term] if has_match
            if mode == SearchMode::INCLUDE && !has_match
              return false
            end
            if mode == SearchMode::EXCLUDE && has_match
              return false
            end
          end

          next
        end

        # The remaining keywords honor 'or' semantics, i.e. the following param_hash will match either osx, or linux
        # {"platform"=>[["osx", "linux"], []]}
        param_hash[keyword][mode].each do |search_term|
          # Reset the match flag for each keyword for inclusive search
          match = false if mode == SearchMode::INCLUDE

          regex = regex_cache[search_term]
          case keyword
            when 'action'
              match = [keyword, search_term] if (module_metadata&.actions || []).any? { |action| action.any? { |k, v| k =~ regex || v =~ regex } }
            when 'aka'
              match = [keyword, search_term] if (module_metadata.notes['AKA'] || []).any? { |aka| aka =~ regex }
            when 'author', 'authors'
              match = [keyword, search_term] if module_metadata.author.any? { |author| author =~ regex }
            when 'arch'
              match = [keyword, search_term] if module_metadata.arch =~ regex
            when 'cve'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref.downcase.start_with?('cve-') && ref =~ regex }
            when 'att&ck', 'attack'
              regex = Regexp.new("\\A#{Regexp.escape(search_term)}(\\.\\d+)*\\Z", Regexp::IGNORECASE)
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref.downcase.start_with?('att&ck-') && ref.downcase.delete_prefix('att&ck-') =~ regex }
            when 'osvdb'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref.downcase.start_with?('osvdb-') && ref =~ regex }
            when 'bid'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref.downcase.start_with?('bid-') && ref =~ regex }
            when 'edb'
              match = [keyword, search_term] if module_metadata.references.any? { |ref| ref.downcase.start_with?('edb-') && ref =~ regex }
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
            when 'fullname'
              match = [keyword, search_term] if module_metadata.fullname =~ regex
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
              match = [keyword, search_term] if module_metadata.fullname =~ regex
            when 'stage'
              match = [keyword, search_term] if module_metadata.stage_refname =~ regex
            when 'stager'
              match = [keyword, search_term] if module_metadata.stager_refname =~ regex
            when 'adapter'
              match = [keyword, search_term] if module_metadata.adapter_refname =~ regex
            when 'session_type'
              match = [keyword, search_term] if module_metadata.session_types && module_metadata.session_types.any? { |session_type| session_type =~ regex }
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
              match = [keyword, search_term] if module_metadata.references && module_metadata.references.any? { |ref| ref =~ regex }
            when 'target', 'targets'
              match = [keyword, search_term] if module_metadata.targets && module_metadata.targets.any? { |target| target =~ regex }
            when 'type'
              match = [keyword, search_term] if Msf::MODULE_TYPES.any? { |module_type| search_term == module_type and module_metadata.type == module_type }
          else
              # Ignore extraneous/invalid keywords
              match = [keyword, search_term]
          end
          break if match
        end
        # Filter this module if no matches for a given keyword type
        if mode == SearchMode::INCLUDE and not match
          return false
        end
      end
      # Filter this module if we matched an exclusion keyword (-value)
      if mode == SearchMode::EXCLUDE and match
        return false
      end
    end

    true
  end

  def as_regex(search_term)
    # Convert into a case-insensitive regex
    utf8_buf = search_term.to_s.dup.force_encoding('UTF-8')
    if utf8_buf.valid_encoding?
       Regexp.new(Regexp.escape(utf8_buf), Regexp::IGNORECASE)
    else
      # If the encoding is invalid, default to a regex that matches anything
      //
    end
  end

  def get_fields(module_metadata, fields)
    selected_fields = {}

    aliases = {
        :cve => 'references',
        :edb => 'references',
        :osvdb => 'references',
        :bid => 'references',
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
