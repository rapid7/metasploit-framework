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

  def is_match(metadata, params)
    match = true
    params.each do |param, value|

      r = Regexp.new(Regexp.escape(value), true)

      case param
      when :app
        (match = match && value == 'client') if metadata.is_client
        (match = match && value == 'server') if metadata.is_server
      when :author
        match = match && metadata.author.any? { |a| a =~ r}
      when :bid
        match = match && metadata.references.any? { |ref| ref =~ /^bid\-/i and ref =~ r }
      when :cve
        match = match && metadata.references.any? { |ref| ref =~ /^cve\-/i and ref =~ r }
      when :edb
        match = match && metadata.references.any? { |ref| ref =~ /^edb\-/i and ref =~ r }
      when :name
        match = match && metadata.name =~ r
      when :os, :platform
        terms = [metadata.platform, metadata.arch]
        if metadata.targets
          terms = terms + metadata.targets
        end
        match = match && terms.any? { |term| term =~ r }
      when :path
        match = match && metadata.full_name =~ r
      when :port
        match = match && metadata.rport =~ r
      when :ref
        match = match && metadata.references.any? { |ref| ref =~ r }
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
    if opts.key? :fields
      fields = opts[:fields].split(',')
      fields.each do | field |
        if module_metadata.respond_to?(field)
          selected_fields[field] = module_metadata.send(field)
        end
      end
    end
    selected_fields.empty? ? module_metadata : selected_fields
  end


end
