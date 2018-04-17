module WorkspaceServlet

    def self.api_path
      '/api/v1/workspaces'
    end

    def self.api_path_with_id
      "#{WorkspaceServlet.api_path}/?:id?"
    end

    def self.registered(app)
      app.get WorkspaceServlet.api_path, &get_workspace
      app.post WorkspaceServlet.api_path, &add_workspace
      app.put WorkspaceServlet.api_path_with_id, &update_workspace
      app.delete WorkspaceServlet.api_path, &delete_workspace
    end

    #######
    private
    #######

    def self.get_workspace
      lambda {
        begin
          opts = parse_json_request(request, false)
          includes = nil
          data = get_db.workspaces(params.symbolize_keys)

          set_json_response(data, includes)
        rescue Exception => e
          set_error_on_response(e)
        end
      }
    end

    def self.add_workspace
      lambda {
        begin
          opts = parse_json_request(request, true)
          workspace = get_db.add_workspace(opts)
          set_json_response(workspace)
        rescue Exception => e
          set_error_on_response(e)
        end
      }
    end

  def self.update_workspace
    lambda {
      begin
        opts = parse_json_request(request, false)
        tmp_params = params.symbolize_keys
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_workspace(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

    def self.delete_workspace
      lambda {
        begin
          opts = parse_json_request(request, false)
          data = get_db.delete_workspaces(opts)
          set_json_response(data)
        rescue Exception => e
          set_error_on_response(e)
        end
      }
    end
end