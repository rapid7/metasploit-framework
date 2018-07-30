module LootServlet

  def self.api_path
    '/api/v1/loots'
  end

  def self.api_path_with_id
    "#{LootServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get LootServlet.api_path, &get_loot
    app.post LootServlet.api_path, &report_loot
    app.put LootServlet.api_path_with_id, &update_loot
    app.delete LootServlet.api_path, &delete_loot
  end

  #######
  private
  #######

  def self.get_loot
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().loots(params.symbolize_keys)
        includes = [:host]
        data.each do |loot|
          loot.data = Base64.urlsafe_encode64(loot.data) if loot.data
        end
        set_json_response(data, includes)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_loot
    lambda {
      job = lambda { |opts|
        if opts[:data]
          filename = File.basename(opts[:path])
          local_path = File.join(Msf::Config.loot_directory, filename)
          opts[:path] = process_file(opts[:data], local_path)
          opts[:data] = Base64.urlsafe_decode64(opts[:data])
        end

        get_db().report_loot(opts)
      }
      exec_report_job(request, &job)
    }
  end

  def self.update_loot
    lambda {
      begin
        opts = parse_json_request(request, false)
        tmp_params = params.symbolize_keys
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db().update_loot(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.delete_loot
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().delete_loot(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end
end