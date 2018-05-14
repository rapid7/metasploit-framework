module LootDataProxy

  def report_loot(opts)
    begin
      data_service = self.get_data_service
      if !data_service.is_a?(Msf::DBManager)
        opts[:data] = Base64.urlsafe_encode64(opts[:data]) if opts[:data]
      end
      add_opts_workspace(opts)
      data_service.report_loot(opts)
    rescue => e
      self.log_error(e, "Problem reporting loot")
    end
  end

  def find_or_create_loot(opts)
    begin
      loot = loots(opts.clone)
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

  def loots(wspace, opts = {})
    begin
      data_service = self.get_data_service
      add_opts_workspace(opts, wspace)
      data_service.loot(opts)
    rescue => e
      self.log_error(e, "Problem retrieving loot")
    end
  end

  alias_method :loot, :loots

  def update_loot(opts)
    begin
      data_service = self.get_data_service
      data_service.update_loot(opts)
    rescue => e
      self.log_error(e, "Problem updating loot")
    end
  end
end