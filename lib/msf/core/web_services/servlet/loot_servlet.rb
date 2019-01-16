module LootServlet

  def self.api_path
    '/api/v1/loots'
  end

  def self.api_path_with_id
    "#{LootServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get LootServlet.api_path_with_id, &get_loot
    app.post LootServlet.api_path, &report_loot
    app.put LootServlet.api_path_with_id, &update_loot
    app.delete LootServlet.api_path, &delete_loot
  end

  #######
  private
  #######

  def self.get_loot
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.loots(sanitized_params)
        includes = [:host]
        data.each do |loot|
          loot.data = Base64.urlsafe_encode64(loot.data) if loot.data
        end
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data, includes: includes)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving the loot:', code: 500)
      end
    }
  end

  def self.report_loot
    lambda {
      warden.authenticate!
      job = lambda { |opts|
        if opts[:data]
          filename = File.basename(opts[:path])
          local_path = File.join(Msf::Config.loot_directory, filename)
          opts[:path] = process_file(opts[:data], local_path)
          opts[:data] = Base64.urlsafe_decode64(opts[:data])
        end

        get_db.report_loot(opts)
      }
      exec_report_job(request, &job)
    }
  end

  def self.update_loot
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_loot(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the loot:', code: 500)
      end
    }
  end

  def self.delete_loot
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_loot(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the loot:', code: 500)
      end
    }
  end
end