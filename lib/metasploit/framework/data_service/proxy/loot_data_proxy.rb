module LootDataProxy

  def report_loot(opts)
    begin
      data_service = self.get_data_service()
      if !data_service.is_a?(Msf::DBManager)
        opts[:data] = Base64.urlsafe_encode64(opts[:data]) if opts[:data]
      end
      data_service.report_loot(opts)
    rescue Exception => e
      elog "Problem reporting loot: #{e.message}"
    end
  end

  def loots(wspace, opts = {})
    begin
      data_service = self.get_data_service
      opts[:wspace] = wspace
      data_service.loot(opts)
    rescue Exception => e
      elog "Problem retrieving loot: #{e.message}"
    end
  end

  alias_method :loot, :loots
end