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

  # Swagger documentation for Host model
  swagger_schema :Host do
    key :required, [:id, :name]
    property :id, type: :integer, format: :int32
    property :created_at, type: :string, format: :date_time
    property :address, type: :string
    property :mac, type: :string
    property :comm, type: :string
    property :name, type: :string
    property :state, type: :string
    property :os_name, type: :string
    property :os_flavor, type: :string
    property :os_sp, type: :string
    property :os_lang, type: :string
    property :arch, type: :string
    property :workspace_id, type: :integer, format: :int32
    property :updated_at, type: :string, format: :date_time
    property :purpose, type: :string
    property :info, type: :string
    property :comments, type: :string
    property :scope, type: :string
    property :virtual_host, type: :string
    property :note_count, type: :integer, format: :int32
    property :vuln_count, type: :integer, format: :int32
    property :service_count, type: :integer, format: :int32
    property :host_detail_count, type: :integer, format: :int32
    property :exploit_attempt_count, type: :integer, format: :int32
    property :cred_count, type: :integer, format: :int32
    property :detected_arch, type: :string
    property :os_family, type: :string
  end

  # Swagger documentation for /api/v1/hosts GET
  swagger_path HostServlet.api_path do
    operation :get do
      key :description, 'Return hosts that are stored in the database.'

      parameter :workspace
      parameter :non_dead
      parameter :address

      response 200 do
        key :description, 'Returns host data'
        schema do
          key :type, :array
          items do
            key :'$ref', :Host
          end
        end
      end
    end
  end

  # Swagger documentation for api/v1/hosts/:id GET
  # Removing the question marks since Swagger doesn't like them
  swagger_path HostServlet.api_path_with_id.gsub('?','') do
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
            key :'$ref', :Host
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

  # Swagger documentation for /api/v1/hosts POST
  swagger_path HostServlet.api_path do
    operation :post do
      key :description, 'Create a host.'

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The attributes to assign to the host'
        key :required, true
        schema do
          key :'$ref', :Host
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Host
        end
      end
    end
  end

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

  # Swagger documentation for /api/v1/hosts/:id PUT
  swagger_path HostServlet.api_path_with_id.gsub('?','') do
    operation :put do
      key :description, 'Update the attributes an existing host.'

      parameter :update_id

      parameter do
        key :in, :body
        key :name, :body
        key :description, 'The updated attributes to overwrite to the host'
        key :required, true
        schema do
          key :'$ref', :Host
        end
      end

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :object
          key :'$ref', :Host
        end
      end
    end
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

  # Swagger documentation for /api/v1/hosts/ DELETE
  swagger_path HostServlet.api_path.gsub('?','') do
    operation :delete do
      key :description, 'Delete the specified hosts.'

      parameter :delete_opts

      response 200 do
        key :description, 'Successful operation'
        schema do
          key :type, :array
          items do
            key :'$ref', :Host
          end
        end
      end
    end
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
