module LootDataProxy

  def report_loot(opts)
    begin
      data_service = self.get_data_service()
      data_service.report_loot(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_loot threw exception: #{e.message}"
    end
  end
end