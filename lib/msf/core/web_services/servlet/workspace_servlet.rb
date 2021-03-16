module Msf::WebServices::WorkspaceServlet

    def self.api_path
      '/api/v1/workspaces'
    end

    def self.api_path_with_id
      "#{self.api_path}/?:id?"
    end

    def self.registered(app)
      app.get self.api_path, &get_workspace
      app.get self.api_path_with_id, &get_workspace
      app.post self.api_path, &add_workspace
      app.put self.api_path_with_id, &update_workspace
      app.delete self.api_path, &delete_workspace
    end

    #######
    private
    #######

    def self.get_workspace
      lambda {
        warden.authenticate!
        begin
          includes = nil

          sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
          data = get_db.workspaces(sanitized_params)
          data = data.first if is_single_object?(data, sanitized_params)
          set_json_data_response(response: data, includes: includes)
        rescue => e
          print_error_and_create_response(error: e, message: 'There was an error retrieving workspaces:', code: 500)
        end
      }
    end

    def self.add_workspace
      lambda {
        warden.authenticate!
        begin
          opts = parse_json_request(request, true)
          data = get_db.add_workspace(opts)
          set_json_data_response(response: data)
        rescue => e
          print_error_and_create_response(error: e, message: 'There was an error creating the workspace:', code: 500)
        end
      }
    end

  def self.update_workspace
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_workspace(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the workspace:', code: 500)
      end
    }
  end

    def self.delete_workspace
      lambda {
        warden.authenticate!
        begin
          opts = parse_json_request(request, false)
          data = get_db.delete_workspaces(opts)
          set_json_data_response(response: data)
        rescue => e
          print_error_and_create_response(error: e, message: 'There was an error deleting the workspaces:', code: 500)
        end
      }
    end
end
