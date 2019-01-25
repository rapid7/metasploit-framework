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
        data = encode_loot_data(data)
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
          local_path = File.join(Msf::Config.loot_directory, "#{SecureRandom.hex(10)}-#{filename}")
          opts[:path] = process_file(opts[:data], local_path)
          opts[:data] = Base64.urlsafe_decode64(opts[:data])
        end

        data = get_db.report_loot(opts)
        encode_loot_data(data)
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
        db_record = get_db.loots(opts).first
        # Give the file a unique name to prevent accidental overwrites. Only do this if there is actually a file
        # on disk. If there is not a file on disk we assume that this DB record is for tracking a file outside
        # of metasploit, so we don't want to assign them a unique file name and overwrite that.
        if opts[:path] && File.exists?(db_record.path)
          filename = File.basename(opts[:path])
          opts[:path] = File.join(Msf::Config.loot_directory, "#{SecureRandom.hex(10)}-#{filename}")
        end
        data = get_db.update_loot(opts)
        data = encode_loot_data(data)
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
        # The rails delete operation returns a frozen object. We need to Base64 encode the data
        # before converting to JSON. So we'll work with a duplicate of the original if it is frozen.
        data.map! { |loot| loot.dup if loot.frozen? }
        data = encode_loot_data(data)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the loot:', code: 500)
      end
    }
  end
end