module Octokit
  class Client

    # Methods for the Apps API
    module Apps

      # Find all installations that belong to an App
      #
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/#find-installations
      #
      # @return [Array<Sawyer::Resource>] the total_count and an array of installations
      def find_app_installations(options = {})
        opts = ensure_api_media_type(:integrations, options)
        paginate "app/installations", opts
      end
      alias find_installations find_app_installations

      def find_integration_installations(options = {})
        octokit_warn(
          "Deprecated: Octokit::Client::Apps#find_integration_installations "\
          "method is deprecated. Please update your call to use "\
          "Octokit::Client::Apps#find_app_installations before the next major "\
          "Octokit version update."
        )
        find_app_installations(options)
      end

      # Find all installations that are accessible to the authenticated user
      #
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/#list-installations-for-user
      #
      # @return [Sawyer::Resource] the total_count and an array of installations
      def find_user_installations(options = {})
        opts = ensure_api_media_type(:integrations, options)
        paginate("user/installations", opts) do |data, last_response|
          data.installations.concat last_response.data.installations
        end
      end

      # Get a single installation
      #
      # @param id [Integer] Installation id
      #
      # @see https://developer.github.com/v3/apps/#get-a-single-installation
      #
      # @return [Sawyer::Resource] Installation information
      def installation(id, options = {})
        opts = ensure_api_media_type(:integrations, options)
        get "app/installations/#{id}", opts
      end

      # Create a new installation token
      #
      # @param installation [Integer] The id of a GitHub App Installation
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/#find-installations
      #
      # @return [<Sawyer::Resource>] An installation token
      def create_app_installation_access_token(installation, options = {})
        opts = ensure_api_media_type(:integrations, options)
        post "app/installations/#{installation}/access_tokens", opts
      end
      alias create_installation_access_token create_app_installation_access_token

      def create_integration_installation_access_token(installation, options = {})
        octokit_warn(
          "Deprecated: Octokit::Client::Apps#create_integration_installation_access_token "\
          "method is deprecated. Please update your call to use "\
          "Octokit::Client::Apps#create_app_installation_access_token before the next major "\
          "Octokit version update."
        )
        create_app_installation_access_token(installation, options)
      end

      # Enables an app to find the organization's installation information.
      #
      # @param organization [String] Organization GitHub login
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/#find-organization-installation
      #
      # @return [Sawyer::Resource] Installation information
      def find_organization_installation(organization, options = {})
        opts = ensure_api_media_type(:integrations, options)
        get "#{Organization.path(organization)}/installation", opts
      end

      # Enables an app to find the repository's installation information.
      #
      # @param repo [String] A GitHub repository
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/#find-repository-installation
      #
      # @return [Sawyer::Resource] Installation information
      def find_repository_installation(repo, options = {})
        opts = ensure_api_media_type(:integrations, options)
        get "#{Repository.path(repo)}/installation", opts
      end

      # Enables an app to find the user's installation information.
      #
      # @param user [String] GitHub user login
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/#find-user-installation
      #
      # @return [Sawyer::Resource] Installation information
      def find_user_installation(user, options = {})
        opts = ensure_api_media_type(:integrations, options)
        get "#{User.path(user)}/installation", opts
      end

      # List repositories that are accessible to the authenticated installation
      #
      # @param options [Hash] A customizable set of options
      # @see https://developer.github.com/v3/apps/installations/#list-repositories
      #
      # @return [Sawyer::Resource] the total_count and an array of repositories
      def list_app_installation_repositories(options = {})
        opts = ensure_api_media_type(:integrations, options)
        paginate("installation/repositories", opts) do |data, last_response|
          data.repositories.concat last_response.data.repositories
        end
      end
      alias list_installation_repos list_app_installation_repositories

      def list_integration_installation_repositories(options = {})
        octokit_warn(
          "Deprecated: Octokit::Client::Apps#list_integration_installation_repositories "\
          "method is deprecated. Please update your call to use "\
          "Octokit::Client::Apps#list_app_installation_repositories before the next major "\
          "Octokit version update."
        )
        list_app_installation_repositories(options)
      end

      # Add a single repository to an installation
      #
      # @param installation [Integer] The id of a GitHub App Installation
      # @param repo [Integer] The id of the GitHub repository
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/installations/#add-repository-to-installation
      #
      # @return [Boolean] Success
      def add_repository_to_app_installation(installation, repo, options = {})
        opts = ensure_api_media_type(:integrations, options)
        boolean_from_response :put, "user/installations/#{installation}/repositories/#{repo}", opts
      end
      alias add_repo_to_installation add_repository_to_app_installation

      def add_repository_to_integration_installation(installation, repo, options = {})
        octokit_warn(
          "Deprecated: Octokit::Client::Apps#add_repository_to_integration_installation "\
          "method is deprecated. Please update your call to use "\
          "Octokit::Client::Apps#add_repository_to_app_installation before the next major "\
          "Octokit version update."
        )
        add_repository_to_app_installation(installation, repo, options)
      end

      # Remove a single repository to an installation
      #
      # @param installation [Integer] The id of a GitHub App Installation
      # @param repo [Integer] The id of the GitHub repository
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/installations/#remove-repository-from-installation
      #
      # @return [Boolean] Success
      def remove_repository_from_app_installation(installation, repo, options = {})
        opts = ensure_api_media_type(:integrations, options)
        boolean_from_response :delete, "user/installations/#{installation}/repositories/#{repo}", opts
      end
      alias remove_repo_from_installation remove_repository_from_app_installation

      def remove_repository_from_integration_installation(installation, repo, options = {})
        octokit_warn(
          "Deprecated: Octokit::Client::Apps#remove_repository_from_integration_installation "\
          "method is deprecated. Please update your call to use "\
          "Octokit::Client::Apps#remove_repository_from_app_installation before the next major "\
          "Octokit version update."
        )
        remove_repository_from_app_installation(installation, repo, options)
      end

      # List repositories accessible to the user for an installation
      #
      # @param installation [Integer] The id of a GitHub App Installation
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/identifying-users-for-github-apps/
      #
      # @return [Sawyer::Resource] the total_count and an array of repositories
      def find_installation_repositories_for_user(installation, options = {})
        opts = ensure_api_media_type(:integrations, options)
        paginate("user/installations/#{installation}/repositories", opts) do |data, last_response|
          data.repositories.concat last_response.data.repositories
        end
      end
    end
  end
end
