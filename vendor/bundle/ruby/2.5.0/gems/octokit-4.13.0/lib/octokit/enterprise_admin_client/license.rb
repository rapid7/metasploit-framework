module Octokit
  class EnterpriseAdminClient

    # Methods for the Enterprise License API
    #
    # @see https://developer.github.com/v3/enterprise-admin/license/
    module License

      # Get information about the Enterprise license
      #
      # @return [Sawyer::Resource] The license information
      def license_info
        get "enterprise/settings/license"
      end

    end
  end
end
