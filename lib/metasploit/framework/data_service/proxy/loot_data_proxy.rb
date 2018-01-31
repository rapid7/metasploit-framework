module LootDataProxy

  def report_loot(opts)
    begin
      data_service = self.get_data_service()
      if !data_service.is_a?(Msf::DBManager)
        opts[:data] = Base64.urlsafe_encode64(opts[:data]) if opts[:data]
      end
      data_service.report_loot(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_loot threw exception: #{e.message}"
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
      puts "Call to #{data_service.class}#loots threw exception: #{e.message}"
      e.backtrace.each { |line| puts "#{line}\n" }
    end
  end
  alias_method :loot, :loots
end