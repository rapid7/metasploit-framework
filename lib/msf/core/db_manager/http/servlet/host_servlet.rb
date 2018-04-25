require 'swagger/blocks'

module HostServlet
  include Swagger::Blocks

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

  # Swagger documentation for /api/v1/hosts
  swagger_path HostServlet.api_path do
    operation :get do
      key :description, 'Return hosts that are stored in the database.'

      parameter do
        key :name, :workspace
        key :in, :query
        key :description, 'The workspace from which the hosts should be gathered from'
        key :required, true
        key :type, :string
      end

      parameter do
        key :name, :non_dead
        key :in, :query
        key :description, 'true to return only hosts which are up, false for all hosts.'
        key :required, false
        key :type, :boolean
      end

      parameter do
        key :name, :address
        key :in, :query
        key :description, 'Return hosts matching the given IP address.'
        key :required, false
        key :type, :string
      end

      response 200 do
        key :description, 'Returns host data'
        schema do
          key :type, :array
          items do
            #key :'$ref', :Host
          end
        end
      end

      response :default do
        key :description, 'test'
        schema do
          key :type, :array
          items do

          end
        end
      end
    end
  end

  # Swagger documentation for api/v1/hosts/:id
  swagger_path HostServlet.api_path_with_id do
    operation :get do
      key :description, 'Return hosts that are stored in the database.'

      parameter :workspace
      parameter :non_dead
      parameter :address

      parameter do
        key :name, :id
        key :in, :path
        key :description, 'ID of host to retrieve'
        key :required, true
        key :type, :integer
        key :format, :int64
      end

      response 200 do
        key :description, 'Returns host data'
        schema do
          key :type, :array
          items do
            #key :'$ref', :Host
          end
        end
      end

      response :default do
        key :description, 'test'
        schema do
          key :type, :array
          items do

          end
        end
      end
    end
  end


  def self.get_host
    lambda {
      begin
        opts = parse_json_request(request, false)
        sanitized_params = sanitize_params(params)
        data = get_db.hosts(sanitized_params)
        includes = [:loots]
        set_json_response(data, includes)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  #
  # @api [post] /api/v1/hosts
  # description: Create a host with the given attributes.
  # parameters:
  #   - (query) workspace {String} The workspace from which the hosts should be gathered from
  #
  def self.report_host
    lambda {
      begin
        job = lambda { |opts|
          data = get_db.report_host(opts)
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
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_host(opts)
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
        data = get_db.delete_host(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

end
