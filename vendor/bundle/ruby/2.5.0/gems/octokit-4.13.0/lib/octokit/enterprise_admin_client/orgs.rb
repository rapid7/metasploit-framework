module Octokit
  class EnterpriseAdminClient

    # Methods for the Enterprise Orgs API
    #
    # @see https://developer.github.com/v3/enterprise-admin/orgs/
    module Orgs

      # Create a new organization on the instance.
      #
      # @param login [String] The organization's username.
      # @param admin [String] The login of the user who will manage this organization.
      # @param options [Hash] A set of options.
      # @option options [String] :profile_name The organization's display name.
      # @return [nil]
      # @see https://developer.github.com/v3/enterprise-admin/orgs/#create-an-organization
      # @example
      #   @admin_client.create_organization('SuchAGreatOrg', 'gjtorikian')
      def create_organization(login, admin, options = {})
        options[:login] = login
        options[:admin] = admin
        post "admin/organizations", options
      end

    end
  end
end
