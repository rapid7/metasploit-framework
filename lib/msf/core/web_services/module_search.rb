module Msf::WebServices::ModuleSearch

  def search_modules(opts)
    raise ::ArgumentError, "At least one search parameter must be provided." if opts.dup.except!(:fields).empty?
    search_results = []
    metadata = Msf::Modules::Metadata::Cache.instance.get_metadata
    params = parse_params(opts)
    metadata.each { |module_metadata|
      if Msf::Modules::Metadata::Cache.instance.matches(params, module_metadata)
        search_results << get_fields(opts, module_metadata)
      end
    }
    search_results
  end

  #######
  private
  #######

  def parse_params(opts)
    # Parse the query params and format the hash to match what the console search `is_match` function expects
    # A param prefixed with '-' indicates "not", and will omit results matching that keyword
    #
    # Resulting Hash Example:
    # {"platform"=>[["android"], []]} will match modules targeting the android platform
    # {"platform"=>[[], ["android"]]} will exclude modules targeting the android platform
    params = {}
    opts.each do |k, v|
      key = k.to_s
      unless key == "fields"
        params[key] = [ [], [] ]
        if v[0, 1] == '-'
          params[key][1] << v[1,v.length-1]
        else
          params[key][0] << v
        end
      end
    end
    params
  end

  def get_fields(opts, module_metadata)
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

    if opts.key? :fields
      fields = opts[:fields].split(',')
      fields.each do | field |
        field.strip!
        field = aliases[field.to_sym] if aliases[field.to_sym]
        if module_metadata.respond_to?(field)
          selected_fields[field] = module_metadata.send(field)
        end
      end
    end
    selected_fields.empty? ? module_metadata : selected_fields
  end


end
