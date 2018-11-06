module Octokit
  class EnterpriseAdminClient

    # Methods for the Enterprise User Administration API
    #
    # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/
    module Users
      # Create a new user.
      #
      # @param login [String] The user's username.
      # @param email [String] The user's email address.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users#create-a-new-user
      # @example
      #   @admin_client.create_user('foobar', 'notreal@foo.bar')
      def create_user(login, email, options = {})
        options[:login] = login
        options[:email] = email
        post "admin/users", options
      end

      # Promote an ordinary user to a site administrator
      #
      # @param user [String] Username of the user to promote.
      # @return [Boolean] True if promote was successful, false otherwise.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#promote-an-ordinary-user-to-a-site-administrator
      # @example
      #   @admin_client.promote('holman')
      def promote(user, options = {})
        boolean_from_response :put, "users/#{user}/site_admin", options
      end

      # Demote a site administrator to an ordinary user
      #
      # @param user [String] Username of the user to demote.
      # @return [Boolean] True if demote was successful, false otherwise.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#demote-a-site-administrator-to-an-ordinary-user
      # @example
      #   @admin_client.demote('holman')
      def demote(user, options = {})
        boolean_from_response :delete, "users/#{user}/site_admin", options
      end

      # Rename a user.
      #
      # @param old_login [String] The user's old username.
      # @param new_login [String] The user's new username.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#rename-an-existing-user
      # @example
      #   @admin_client.rename_user('foobar', 'foofoobar')
      def rename_user(old_login, new_login, options = {})
        options[:login] = new_login
        patch "admin/users/#{old_login}", options
      end

      # Deletes a user.
      #
      # @param username [String] The username to delete.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#delete-a-user
      # @example
      #   @admin_client.delete_key(1)
      def delete_user(username, options = {})
        boolean_from_response :delete,  "admin/users/#{username}", options
      end

      # Suspend a user.
      #
      # @param user [String] Username of the user to suspend.
      # @return [Boolean] True if suspend was successful, false otherwise.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#suspend-a-user
      # @example
      #   @admin_client.suspend('holman')
      def suspend(user, options = {})
        boolean_from_response :put, "users/#{user}/suspended", options
      end

      # Unsuspend a user.
      #
      # @param user [String] Username of the user to unsuspend.
      # @return [Boolean] True if unsuspend was successful, false otherwise.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#unsuspend-a-user
      # @example
      #   @admin_client.unsuspend('holman')
      def unsuspend(user, options = {})
        boolean_from_response :delete, "users/#{user}/suspended", options
      end

      # Creates an impersonation OAuth token.
      #
      # @param login [String] The user to create a token for.
      # @param options [Array<String>] :scopes The scopes to apply.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#create-an-impersonation-oauth-token
      # @example
      #   @admin_client.create_impersonation_token('foobar', {:scopes => ['repo:write']})
      def create_impersonation_token(login, options = {})
        post "admin/users/#{login}/authorizations", options
      end

      # Deletes an impersonation OAuth token.
      #
      # @param login [String] The user whose token should be deleted.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#delete-an-impersonation-oauth-token
      # @example
      #   @admin_client.delete_impersonation_token('foobar')
      def delete_impersonation_token(login, options = {})
        boolean_from_response :delete, "admin/users/#{login}/authorizations", options
      end

      # Lists all the public SSH keys.
      #
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#list-all-public-keys
      # @example
      #   @admin_client.list_all_keys
      def list_all_keys(options = {})
        get "admin/keys", options
      end

      # Deletes a public SSH keys.
      #
      # @param id [Number] The ID of the key to delete.
      # @see https://developer.github.com/enterprise/v3/enterprise-admin/users/#delete-a-public-key
      # @example
      #   @admin_client.delete_key(1)
      def delete_key(id, options = {})
        boolean_from_response :delete,  "admin/keys/#{id}", options
      end
    end
  end
end
