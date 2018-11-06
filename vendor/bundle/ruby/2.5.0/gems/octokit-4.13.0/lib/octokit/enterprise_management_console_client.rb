require 'octokit/configurable'
require 'octokit/connection'
require 'octokit/warnable'
require 'octokit/enterprise_management_console_client/management_console'

module Octokit

  # EnterpriseManagementConsoleClient is only meant to be used by GitHub Enterprise Admins
  # and provides access to the management console API endpoints.
  #
  # @see Octokit::Client Use Octokit::Client for regular API use for GitHub
  #   and GitHub Enterprise.
  # @see https://developer.github.com/v3/enterprise-admin/management_console/
  class EnterpriseManagementConsoleClient

    include Octokit::Configurable
    include Octokit::Connection
    include Octokit::Warnable
    include Octokit::EnterpriseManagementConsoleClient::ManagementConsole

    def initialize(options = {})
      # Use options passed in, but fall back to module defaults
      Octokit::Configurable.keys.each do |key|
        instance_variable_set(:"@#{key}", options[key] || Octokit.instance_variable_get(:"@#{key}"))
      end
    end

    protected

    def endpoint
      management_console_endpoint
    end

    # Set Enterprise Management Console password
    #
    # @param value [String] Management console admin password
    def management_console_password=(value)
      reset_agent
      @management_console_password = value
    end

    # Set Enterprise Management Console endpoint
    #
    # @param value [String] Management console endpoint
    def management_console_endpoint=(value)
      reset_agent
      @management_console_endpoint = value
    end
  end
end
