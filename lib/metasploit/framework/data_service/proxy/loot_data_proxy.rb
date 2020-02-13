module LootDataProxy

  def report_loot(opts)
    begin
      self.data_service_operation do |data_service|
        if !data_service.is_a?(Msf::DBManager)
          opts[:data] = Base64.urlsafe_encode64(opts[:data].empty? ? "" : opts[:data].join('')) if opts[:data] and opts[:data].kind_of?(Array) else opts[:data]
        end
        add_opts_workspace(opts)
        data_service.report_loot(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting loot")
    end
  end

  def find_or_create_loot(opts)
    begin
      # create separate opts for find operation since the report operation uses slightly different keys
      # TODO: standardize option keys used for the find and report operations
      find_opts = opts.clone
      # convert type to ltype
      find_opts[:ltype] = find_opts.delete(:type) if find_opts.key?(:type)
      # convert host to nested hosts address
      find_opts[:hosts] = {address: find_opts.delete(:host)} if find_opts.key?(:host)

      loot = loots(find_opts)
      if loot.nil? || loot.first.nil?
        loot = report_loot(opts.clone)
      else
        loot = loot.first
      end
      loot
    rescue => e
      self.log_error(e, "Problem finding or creating loot")
    end
  end

  def loots(opts = {})
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.loot(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving loot")
    end
  end

  alias_method :loot, :loots

  def update_loot(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_loot(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating loot")
    end
  end
end
