module Msf::DBManager::Search
  # Wraps values in +'%'+ for Arel::Prediciation#matches_any and other match* methods that map to SQL +'LIKE'+ or
  # +'ILIKE'+
  #
  # @param values [Set<String>, #each] a list of strings.
  # @return [Arrray<String>] strings wrapped like %<string>%
  def match_values(values)
    wrapped_values = values.collect { |value|
      "%#{value}%"
    }

    wrapped_values
  end

  # This provides a standard set of search filters for every module.
  #
  # Supported keywords with the format <keyword>:<search_value>:
  # +app+:: If +client+ then matches +'passive'+ stance modules, otherwise matches +'active' stance modules.
  # +author+:: Matches modules with the given author email or name.
  # +bid+:: Matches modules with the given Bugtraq ID.
  # +cve+:: Matches modules with the given CVE ID.
  # +edb+:: Matches modules with the given Exploit-DB ID.
  # +name+:: Matches modules with the given full name or name.
  # +os+, +platform+:: Matches modules with the given platform or target name.
  # +osvdb+:: Matches modules with the given OSVDB ID.
  # +ref+:: Matches modules with the given reference ID.
  # +type+:: Matches modules with the given type.
  #
  # Any text not associated with a keyword is matched against the description,
  # the full name, and the name of the module; the name of the module actions;
  # the name of the module archs; the name of the module authors; the name of
  # module platform; the module refs; or the module target.
  #
  # @param search_string [String] a string of space separated keyword pairs or
  #   free form text.
  # @return [[]] if search_string is +nil+
  # @return [ActiveRecord::Relation] module details that matched
  #   +search_string+
  def search_modules(search_string)
    search_string ||= ''
    search_string += " "

    # Split search terms by space, but allow quoted strings
    terms = Shellwords.shellwords(search_string)
    terms.delete('')

    # All terms are either included or excluded
    value_set_by_keyword = Hash.new { |hash, keyword|
      hash[keyword] = Set.new
    }

    terms.each do |term|
      keyword, value = term.split(':', 2)

      unless value
        value = keyword
        keyword = 'text'
      end

      unless value.empty?
        keyword.downcase!

        value_set = value_set_by_keyword[keyword]
        value_set.add value
      end
    end

    query = Mdm::Module::Detail.scoped

    ActiveRecord::Base.connection_pool.with_connection do
      # Although AREL supports taking the union or two queries, the ActiveRecord where syntax only supports
      # intersection, so creating the where clause has to be delayed until all conditions can be or'd together and
      # passed to one call ot where.
      union_conditions = []

      value_set_by_keyword.each do |keyword, value_set|
        case keyword
          when 'author'
            formatted_values = match_values(value_set)

            query = query.includes(:authors)
            module_authors = Mdm::Module::Author.arel_table
            union_conditions << module_authors[:email].matches_any(formatted_values)
            union_conditions << module_authors[:name].matches_any(formatted_values)
          when 'name'
            formatted_values = match_values(value_set)

            module_details = Mdm::Module::Detail.arel_table
            union_conditions << module_details[:fullname].matches_any(formatted_values)
            union_conditions << module_details[:name].matches_any(formatted_values)
          when 'os', 'platform'
            formatted_values = match_values(value_set)

            query = query.includes(:platforms)
            union_conditions << Mdm::Module::Platform.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:targets)
            union_conditions << Mdm::Module::Target.arel_table[:name].matches_any(formatted_values)
          when 'text'
            formatted_values = match_values(value_set)

            module_details = Mdm::Module::Detail.arel_table
            union_conditions << module_details[:description].matches_any(formatted_values)
            union_conditions << module_details[:fullname].matches_any(formatted_values)
            union_conditions << module_details[:name].matches_any(formatted_values)

            query = query.includes(:actions)
            union_conditions << Mdm::Module::Action.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:archs)
            union_conditions << Mdm::Module::Arch.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:authors)
            union_conditions << Mdm::Module::Author.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:platforms)
            union_conditions << Mdm::Module::Platform.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:refs)
            union_conditions << Mdm::Module::Ref.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:targets)
            union_conditions << Mdm::Module::Target.arel_table[:name].matches_any(formatted_values)
          when 'type'
            formatted_values = match_values(value_set)
            union_conditions << Mdm::Module::Detail.arel_table[:mtype].matches_any(formatted_values)
          when 'app'
            formatted_values = value_set.collect { |value|
              formatted_value = 'aggressive'

              if value == 'client'
                formatted_value = 'passive'
              end

              formatted_value
            }

            union_conditions << Mdm::Module::Detail.arel_table[:stance].eq_any(formatted_values)
          when 'ref'
            formatted_values = match_values(value_set)

            query = query.includes(:refs)
            union_conditions << Mdm::Module::Ref.arel_table[:name].matches_any(formatted_values)
          when 'cve', 'bid', 'osvdb', 'edb'
            formatted_values = value_set.collect { |value|
              prefix = keyword.upcase

              "#{prefix}-%#{value}%"
            }

            query = query.includes(:refs)
            union_conditions << Mdm::Module::Ref.arel_table[:name].matches_any(formatted_values)
        end
      end

      unioned_conditions = union_conditions.inject { |union, condition|
        union.or(condition)
      }

      query = query.where(unioned_conditions).uniq
    end

    query
  end
end