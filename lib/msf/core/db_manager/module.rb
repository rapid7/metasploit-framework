module Msf::DBManager::Module

  def modules(opts)
    search_results = []
    metadata = Msf::Modules::Metadata::Cache.instance.get_metadata
    metadata.each { |module_metadata|
      if is_match(module_metadata, opts)
        search_results << get_fields(module_metadata, opts)
      end
    }
    search_results
  end

  #######
  private
  #######

  def is_match(metadata, params)
    match = true
    params.each do |param, value|

      r = Regexp.new(Regexp.escape(value), true)

      case param
      when :app
        (match = match && value == 'client') if metadata.is_client
        (match = match && value == 'server') if metadata.is_server
      when :author, :authors
        match = match && metadata.author.any? { |a| a =~ r}
      when :arch
        match = match && metadata.arch =~ r
      when :bid
        match = match && metadata.references.any? { |ref| ref =~ /^bid\-/i and ref =~ r }
      when :cve
        match = match && metadata.references.any? { |ref| ref =~ /^cve\-/i and ref =~ r }
      when :edb
        match = match && metadata.references.any? { |ref| ref =~ /^edb\-/i and ref =~ r }
      when :description
        match = match && metadata.description =~ r
      when :date, :disclosure_date
        match = match && metadata.disclosure_date.to_s =~ r
      when :full_name, :fullname
        match = match && metadata.full_name =~ r
      when :is_client
        match = match && value == (metadata.is_client).to_s
      when :is_server
        match = match && value == (metadata.is_server).to_s
      when :is_install_path
        match = match && value == (metadata.is_install_path).to_s
      when :mod_time
        match = match && metadata.mod_time.to_s =~ r
      when :name
        match = match && metadata.name =~ r
      when :os, :platform
        terms = [metadata.platform, metadata.arch]
        if metadata.targets
          terms = terms + metadata.targets
        end
        match = match && terms.any? { |term| term =~ r }
      when :path
        match = match && metadata.path =~ r
      when :port, :rport
        match = match && metadata.rport =~ r
      when :rank
        # Determine if param was prepended with gt, lt, gte, lte, or eq
        # Ex: "lte300" should match all ranks <= 300
        query_rank = value.dup
        operator = query_rank[0, 3].tr("0-9", "")
        matches_rank = metadata.rank == value.to_i
        unless operator.empty?
          query_rank.slice! operator
          query_rank = query_rank.to_i
          case operator
          when 'gt'
            matches_rank = metadata.rank.to_i > query_rank
          when 'lt'
            matches_rank = metadata.rank.to_i < query_rank
          when 'gte'
            matches_rank = metadata.rank.to_i >= query_rank
          when 'lte'
            matches_rank = metadata.rank.to_i <= query_rank
          when 'eq'
            matches_rank = metadata.rank.to_i == query_rank
          end
        end
        match = match && matches_rank
      when :ref, :ref_name
        match = match && metadata.ref_name =~ r
      when :reference, :references
        match = match && metadata.references.any? { |ref| ref =~ r }
      when :target, :targets
        match = match && metadata.targets.any? { |target| target =~ r }
      when :text
        terms = [metadata.name, metadata.full_name, metadata.description] + metadata.references + metadata.author
        if metadata.targets
          terms = terms + metadata.targets
        end
        match = match && terms.any? { |term| term =~ r}
      when :type
        match = match && (Msf::MODULE_TYPES.any? { |type| value == type and metadata.type == type })
      end
    end
    match
  end

  def get_fields(module_metadata, opts)
    selected_fields = {}

    aliases = {
      :cve => 'references',
      :edb => 'references',
      :bid => 'references',
      :fullname => 'full_name',
      :os => 'platform',
      :port => 'rport',
      :reference => 'references',
      :target => 'targets',
      :authors => 'author'
    }

    if opts.key? :fields
      fields = opts[:fields].split(',')
      fields.each do | field |
        field = aliases[field.to_sym] if aliases[field.to_sym]
        if module_metadata.respond_to?(field)
          selected_fields[field] = module_metadata.send(field)
        end
      end
    end
    selected_fields.empty? ? module_metadata : selected_fields
  end


end
