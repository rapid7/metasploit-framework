module VulnServlet

  def self.api_path
    '/api/v1/vulns'
  end

  def self.api_path_with_id
    "#{VulnServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get VulnServlet.api_path_with_id, &get_vuln
    app.post VulnServlet.api_path, &report_vuln
    app.put VulnServlet.api_path_with_id, &update_vuln
    app.delete VulnServlet.api_path, &delete_vuln
  end

  #######
  private
  #######

  def self.get_vuln
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.vulns(sanitized_params)
        includes = [:host, :vulns_refs, :refs, :module_refs]
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data, includes: includes)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving vulns:', code: 500)
      end
    }
  end

  def self.report_vuln
    lambda {
      warden.authenticate!
      job = lambda { |opts|
        get_db.report_vuln(opts)
      }
      exec_report_job(request, &job)
    }
  end

  def self.update_vuln
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_vuln(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the vuln:', code: 500)
      end
    }
  end

  def self.delete_vuln
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_vuln(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the vulns:', code: 500)
      end
    }
  end

end