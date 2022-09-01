module Msf::WebServices::ModuleSearch

  def search_modules(opts)
    raise ::ArgumentError, "At least one search parameter must be provided." if opts.except(:fields).empty?
    params = parse_params(opts)
    fields = parse_fields(opts)
    begin
      Msf::Modules::Metadata::Cache.instance.find(params, fields)
    rescue ArgumentError
      raise ::ArgumentError, "Invalid search parameter(s) provided."
    end
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
    opts.each do | k, v |
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

  def parse_fields(opts)
    fields = []
    if opts.key? :fields
      fields = opts[:fields].split(',')
      fields.each do | field |
        field.strip!
      end
    end
    fields
  end

end
