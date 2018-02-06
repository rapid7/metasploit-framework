module HostServlet

  def self.api_path
    '/api/v1/hosts'
  end

  def self.api_path_with_id
    "#{HostServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get HostServlet.api_path_with_id, &get_host
    app.post HostServlet.api_path, &report_host
    app.put HostServlet.api_path_with_id, &update_host
    app.delete HostServlet.api_path, &delete_host
  end

  #######
  private
  #######

  def self.get_host
    lambda {
      begin
        $stderr.puts "HostServlet.get_host(): params[:id] = #{params[:id]}" if params[:id]  # TODO: remove
        opts = parse_json_request(request, false)
        data = get_db().hosts(params.symbolize_keys)
        includes = [:loots]
        set_json_response(data, includes)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_host
    lambda {
      begin
        job = lambda { |opts|
          data = get_db().report_host(opts)
        }
        exec_report_job(request, &job)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.update_host
    lambda {
      begin
        opts = parse_json_request(request, false)
        $stderr.puts "HostServlet.update_host(): opts = #{opts}"  # TODO: remove
        $stderr.puts "HostServlet.update_host(): params = #{params}"  # TODO: remove
        # opts_and_params = params ? opts.merge(params.symbolize_keys) : opts
        tmp_params = params.symbolize_keys
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        $stderr.puts "HostServlet.update_host(): opts = #{opts}"  # TODO: remove
        data = get_db().update_host(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.delete_host
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().delete_host(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

end
