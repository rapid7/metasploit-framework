require 'sinatra/base'
require 'uri'

require 'metasploit/framework/data_service/remote/http/core'
require 'msf/base/simple/framework'

module Msf::WebServices
  # Extension provides a Metasploit Framework instance to a Sinatra application.
  # The framework instance is stored with the setting name framework and is
  # also accessible via the framework helper method. If the data service URL
  # environment variable is set, then the framework instance will be configured
  # to use the data service rather than the local database.
  #
  # Environment Variables:
  # MSF_WS_DATA_SERVICE_URL - The data service URL.
  # MSF_WS_DATA_SERVICE_API_TOKEN - API token used to authenticate to the remote data service.
  # MSF_WS_DATA_SERVICE_CERT - Certificate file matching the remote data server's certificate.
  #                            Needed when using self-signed SSL certificates.
  # MSF_WS_DATA_SERVICE_SKIP_VERIFY - (Boolean) Skip validating authenticity of server's certificate.
  module FrameworkExtension
    FALSE_VALUES = [nil, false, 0, '0', 'f', 'false', 'off', 'no'].to_set

    module Helpers
      # Get framework instance from settings.
      def framework
        settings.framework
      end
    end

    def self.registered(app)
      app.helpers FrameworkExtension::Helpers

      app.set :data_service_url, ENV.fetch('MSF_WS_DATA_SERVICE_URL', nil)
      app.set :data_service_api_token, ENV.fetch('MSF_WS_DATA_SERVICE_API_TOKEN', nil)
      app.set :data_service_cert, ENV.fetch('MSF_WS_DATA_SERVICE_CERT', nil)
      app.set :data_service_skip_verify, to_bool(ENV.fetch('MSF_WS_DATA_SERVICE_SKIP_VERIFY', false))

      # Create simplified instance of the framework
      app.set :framework, Msf::Simple::Framework.create

      if !app.settings.data_service_url.nil? && !app.settings.data_service_url.empty?
        framework_db_connect_http_data_service(framework: app.settings.framework,
                                               data_service_url: app.settings.data_service_url,
                                               api_token: app.settings.data_service_api_token,
                                               cert: app.settings.data_service_cert,
                                               skip_verify: app.settings.data_service_skip_verify)
      end
    end

    def self.framework_db_connect_http_data_service(
        framework:, data_service_url:, api_token: nil, cert: nil, skip_verify: false)
      # local database is required to use Mdm objects
      unless framework.db.active
        raise "No local database connected"
      end

      opts = {}
      https_opts = {}
      opts[:url] = data_service_url unless data_service_url.nil?
      opts[:api_token] = api_token unless api_token.nil?
      https_opts[:cert] = cert unless cert.nil?
      https_opts[:skip_verify] = skip_verify if skip_verify
      opts[:https_opts] = https_opts unless https_opts.empty?

      begin
        uri = URI.parse(data_service_url)
        remote_data_service = Metasploit::Framework::DataService::RemoteHTTPDataService.new(uri.to_s, opts)
        framework.db.register_data_service(remote_data_service)
        framework.db.workspace = framework.db.default_workspace
      rescue => e
        raise "Failed to connect to the HTTP data service: #{e.message}"
      end
    end

    private

    def self.to_bool(value)
      if value.is_a?(String)
        value = value.downcase
      end

      !FALSE_VALUES.include?(value)
    end
  end
end