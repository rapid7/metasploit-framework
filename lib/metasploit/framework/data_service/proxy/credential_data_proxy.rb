module CredentialDataProxy

  def create_credential(opts)
    begin
      data_service = self.get_data_service()
      if !data_service.is_a?(Msf::DBManager)
        opts[:data] = Base64.urlsafe_encode64(opts[:data]) if opts[:data]
      end
      data_service.create_credential(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#create_credential threw exception: #{e.message}"
    end
  end

  def creds(opts = {})
    begin
      data_service = self.get_data_service
      data_service.creds(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#credentials threw exception: #{e.message}"
      e.backtrace.each { |line| puts "#{line}\n" }
    end
  end
end