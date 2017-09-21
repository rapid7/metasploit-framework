module LootDataProxy

  def report_loot(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_loot(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_loot threw exception: #{e.message}"
    end
  end

  def loots(wspace, non_dead = false, addresses = nil)
    begin
      data_service = self.get_data_service
      opts = {}
      opts[:wspace] = wspace
      opts[:non_dead] = non_dead
      opts[:addresses] = addresses
      data_service.loot(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#loots threw exception: #{e.message}"
      e.backtrace.each { |line| puts "#{line}\n" }
    end
  end
  alias_method :loot, :loots
end