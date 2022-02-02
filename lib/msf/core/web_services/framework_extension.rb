require 'sinatra/base'
require 'uri'

require 'metasploit/framework/data_service/remote/http/core'

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
  # MSF_WS_DATA_SERVICE_LOGGER - (String) The logger that framework will use. By default logs will be
  #                             placed in ``~/.msf4/logs`
  module FrameworkExtension
    FALSE_VALUES = [nil, false, 0, '0', 'f', 'false', 'off', 'no'].to_set

    module Helpers
      # Get framework instance from settings.
      def framework
        settings.framework
      end

      def get_db
        framework.db
      end
    end

    def self.registered(app)
      app.helpers FrameworkExtension::Helpers

      app.set :data_service_url, ENV.fetch('MSF_WS_DATA_SERVICE_URL', nil)
      app.set :data_service_api_token, ENV.fetch('MSF_WS_DATA_SERVICE_API_TOKEN', nil)
      app.set :data_service_cert, ENV.fetch('MSF_WS_DATA_SERVICE_CERT', nil)
      app.set :data_service_skip_verify, to_bool(ENV.fetch('MSF_WS_DATA_SERVICE_SKIP_VERIFY', false))

      @@framework = nil
      # Create simplified instance of the framework
      app.set :framework, (proc {
        @@framework ||= begin
          init_framework_opts = {
            'Logger' => ENV.fetch('MSF_WS_DATA_SERVICE_LOGGER', nil),
            # SkipDatabaseInit false is the default behavior, however for explicitness - note that framework first
            # connects to a local database as a pre-requisite to connecting to a remote service to correctly
            # configure active record
            'SkipDatabaseInit' => false
          }
          framework = Msf::Simple::Framework.create(init_framework_opts)
          Msf::WebServices::FrameworkExtension.db_connect(framework, app)

          framework
        end
      })
    end

    def self.db_connect(framework, app)
      if !app.settings.data_service_url.nil? && !app.settings.data_service_url.empty?
        options = {
          url: app.settings.data_service_url,
          api_token: app.settings.data_service_api_token,
          cert: app.settings.data_service_cert,
          skip_verify: app.settings.data_service_skip_verify
        }
        db_result = Msf::DbConnector.db_connect(framework, options)
      else
        db_result = Msf::DbConnector.db_connect_from_config(framework)
      end

      if db_result[:error]
        raise db_result[:error]
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
