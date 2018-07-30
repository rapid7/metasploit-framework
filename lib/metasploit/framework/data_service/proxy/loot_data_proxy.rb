module LootDataProxy

  def report_loot(opts)
    begin
      data_service = self.get_data_service()
      if !data_service.is_a?(Msf::DBManager)
        opts[:data] = Base64.urlsafe_encode64(opts[:data]) if opts[:data]
      end
      data_service.report_loot(opts)
    rescue Exception => e
      self.log_error(e, "Problem reporting loot")
    end
  end

  # TODO: Shouldn't this proxy to RemoteLootDataService#find_or_create_loot ?
  # It's currently skipping the "find" part
  def find_or_create_loot(opts)
    report_loot(opts)
  end

  def loots(wspace, opts = {})
    begin
      data_service = self.get_data_service
      opts[:wspace] = wspace
      data_service.loot(opts)
    rescue Exception => e
      self.log_error(e, "Problem retrieving loot")
    end
  end

  alias_method :loot, :loots

  def update_loot(opts)
    begin
      data_service = self.get_data_service
      data_service.update_loot(opts)
    rescue Exception => e
      self.log_error(e, "Problem updating loot")
    end
  end
end