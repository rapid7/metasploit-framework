module LootServlet

  def self.api_path
    '/api/1/msf/loot'
  end

  def self.registered(app)
    app.get LootServlet.api_path, &get_loot
    app.post LootServlet.api_path, &report_loot
  end

  #######
  private
  #######

  def self.get_loot
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().hosts(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_loot
    lambda {
      job = lambda { |opts| get_db().report_host(opts) }
      exec_report_job(request, &job)
    }
  end
end