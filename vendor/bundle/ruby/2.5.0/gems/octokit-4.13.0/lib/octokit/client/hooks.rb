module Octokit
  class Client

    # Methods for the Hooks API
    module Hooks

      # List all Service Hooks supported by GitHub
      #
      # @return [Sawyer::Resource] A list of all hooks on GitHub
      # @see https://developer.github.com/v3/repos/hooks/#services
      # @example List all hooks
      #   Octokit.available_hooks
      def available_hooks(options = {})
        get "hooks", options
      end

      # List repo hooks
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing hooks.
      # @see https://developer.github.com/v3/repos/hooks/#list-hooks
      # @example
      #   @client.hooks('octokit/octokit.rb')
      def hooks(repo, options = {})
        paginate "#{Repository.path repo}/hooks", options
      end

      # Get single hook
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Id of the hook to get.
      # @return [Sawyer::Resource] Hash representing hook.
      # @see https://developer.github.com/v3/repos/hooks/#get-single-hook
      # @example
      #   @client.hook('octokit/octokit.rb', 100000)
      def hook(repo, id, options = {})
        get "#{Repository.path repo}/hooks/#{id}", options
      end

      # Create a hook
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param name [String] The name of the service that is being called. See
      #   {https://api.github.com/hooks Hooks} for the possible names.
      # @param config [Hash] A Hash containing key/value pairs to provide
      #   settings for this hook. These settings vary between the services and
      #   are defined in the {https://github.com/github/github-services github-services} repo.
      # @option options [Array<String>] :events ('["push"]') Determines what
      #   events the hook is triggered for.
      # @option options [Boolean] :active Determines whether the hook is
      #   actually triggered on pushes.
      # @return [Sawyer::Resource] Hook info for the new hook
      # @see https://api.github.com/hooks
      # @see https://github.com/github/github-services
      # @see https://developer.github.com/v3/repos/hooks/#create-a-hook
      # @example
      #   @client.create_hook(
      #     'octokit/octokit.rb',
      #     'web',
      #     {
      #       :url => 'http://something.com/webhook',
      #       :content_type => 'json'
      #     },
      #     {
      #       :events => ['push', 'pull_request'],
      #       :active => true
      #     }
      #   )
      def create_hook(repo, name, config, options = {})
        options = {:name => name, :config => config, :events => ["push"], :active => true}.merge(options)
        post "#{Repository.path repo}/hooks", options
      end

      # Edit a hook
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Id of the hook being updated.
      # @param name [String] The name of the service that is being called. See
      #   {https://api.github.com/hooks Hooks} for the possible names.
      # @param config [Hash] A Hash containing key/value pairs to provide
      #   settings for this hook. These settings vary between the services and
      #   are defined in the {https://github.com/github/github-services github-services} repo.
      # @option options [Array<String>] :events ('["push"]') Determines what
      #   events the hook is triggered for.
      # @option options [Array<String>] :add_events Determines a list of events
      #   to be added to the list of events that the Hook triggers for.
      # @option options [Array<String>] :remove_events Determines a list of events
      #   to be removed from the list of events that the Hook triggers for.
      # @option options [Boolean] :active Determines whether the hook is
      #   actually triggered on pushes.
      # @return [Sawyer::Resource] Hook info for the updated hook
      # @see https://api.github.com/hooks
      # @see https://github.com/github/github-services
      # @see https://developer.github.com/v3/repos/hooks/#edit-a-hook
      # @example
      #   @client.edit_hook(
      #     'octokit/octokit.rb',
      #     100000,
      #     'web',
      #     {
      #       :url => 'http://something.com/webhook',
      #       :content_type => 'json'
      #     },
      #     {
      #       :add_events => ['status'],
      #       :remove_events => ['pull_request'],
      #       :active => true
      #     }
      #   )
      def edit_hook(repo, id, name, config, options = {})
        options = {:name => name, :config => config}.merge(options)
        patch "#{Repository.path repo}/hooks/#{id}", options
      end

      # Delete hook
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Id of the hook to remove.
      # @return [Boolean] True if hook removed, false otherwise.
      # @see https://developer.github.com/v3/repos/hooks/#delete-a-hook
      # @example
      #   @client.remove_hook('octokit/octokit.rb', 1000000)
      def remove_hook(repo, id, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/hooks/#{id}", options
      end

      # Test hook
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Id of the hook to test.
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/repos/hooks/#test-a-push-hook
      # @example
      #   @client.test_hook('octokit/octokit.rb', 1000000)
      def test_hook(repo, id, options = {})
        boolean_from_response :post, "#{Repository.path repo}/hooks/#{id}/tests", options
      end

      # Ping hook
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Id of the hook to send a ping.
      # @return [Boolean] Ping requested?
      # @see https://developer.github.com/v3/repos/hooks/#ping-a-hook
      # @example
      #   @client.ping_hook('octokit/octokit.rb', 1000000)
      def ping_hook(repo, id, options={})
        boolean_from_response :post, "#{Repository.path repo}/hooks/#{id}/pings", options
      end

      # List org hooks
      #
      # Requires client authenticated as admin for the org.
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @return [Array<Sawyer::Resource>] Array of hashes representing hooks.
      # @see https://developer.github.com/v3/orgs/hooks/#list-hooks
      # @example
      #   @client.org_hooks('octokit')
      def org_hooks(org, options = {})
        paginate "#{Organization.path org}/hooks", options
      end
      alias :list_org_hooks :org_hooks

      # Get an org hook
      #
      # Requires client authenticated as admin for the org.
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @param id [Integer] Id of the hook to get.
      # @return [Sawyer::Resource] Hash representing hook.
      # @see https://developer.github.com/v3/orgs/hooks/#get-single-hook
      # @example
      #   @client.org_hook('octokit', 123)
      def org_hook(org, id, options = {})
        get "#{Organization.path org}/hooks/#{id}", options
      end

      # Create an org hook
      #
      # Requires client authenticated as admin for the org.
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @param config [Hash] A Hash containing key/value pairs to provide
      #   settings for this hook.
      # @option options [Array<String>] :events ('["push"]') Determines what
      #   events the hook is triggered for.
      # @option options [Boolean] :active Determines whether the hook is
      #   actually triggered on pushes.
      # @return [Sawyer::Resource] Hook info for the new hook
      # @see https://api.github.com/hooks
      # @see https://developer.github.com/v3/orgs/hooks/#create-a-hook
      # @example
      #   @client.create_org_hook(
      #     'octokit',
      #     {
      #       :url => 'http://something.com/webhook',
      #       :content_type => 'json'
      #     },
      #     {
      #       :events => ['push', 'pull_request'],
      #       :active => true
      #     }
      #   )
      def create_org_hook(org, config, options = {})
        options = { :name => "web", :config => config }.merge(options)
        post "#{Organization.path org}/hooks", options
      end

      # Update an org hook
      #
      # Requires client authenticated as admin for the org.
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @param id [Integer] Id of the hook to update.
      # @param config [Hash] A Hash containing key/value pairs to provide
      #   settings for this hook.
      # @option options [Array<String>] :events ('["push"]') Determines what
      #   events the hook is triggered for.
      # @option options [Boolean] :active Determines whether the hook is
      #   actually triggered on pushes.
      # @return [Sawyer::Resource] Hook info for the new hook
      # @see https://api.github.com/hooks
      # @see https://developer.github.com/v3/orgs/hooks/#edit-a-hook
      # @example
      #   @client.edit_org_hook(
      #     'octokit',
      #     123,
      #     {
      #       :url => 'http://something.com/webhook',
      #       :content_type => 'json'
      #     },
      #     {
      #       :events => ['push', 'pull_request'],
      #       :active => true
      #     }
      #   )
      def edit_org_hook(org, id, config, options = {})
        options = { :config => config }.merge(options)
        patch "#{Organization.path org}/hooks/#{id}", options
      end
      alias :update_org_hook :edit_org_hook

      # Ping org hook
      #
      # Requires client authenticated as admin for the org.
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @param id [Integer] Id of the hook to update.
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/orgs/hooks/#ping-a-hook
      # @example
      #   @client.ping_org_hook('octokit', 1000000)
      def ping_org_hook(org, id, options = {})
        boolean_from_response :post, "#{Organization.path org}/hooks/#{id}/pings", options
      end

      # Remove org hook
      #
      # Requires client authenticated as admin for the org.
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @param id [Integer] Id of the hook to update.
      # @return [Boolean] True if hook removed, false otherwise.
      # @see https://developer.github.com/v3/orgs/hooks/#delete-a-hook
      # @example
      #   @client.remove_org_hook('octokit', 1000000)
      def remove_org_hook(org, id, options = {})
        boolean_from_response :delete, "#{Organization.path org}/hooks/#{id}", options
      end

      # Parse payload string
      #
      # @param payload_string [String] The payload
      # @return [Sawyer::Resource] The payload object
      # @see https://developer.github.com/v3/activity/events/types/
      def parse_payload(payload_string)
        payload_hash = agent.class.decode payload_string
        Sawyer::Resource.new agent, payload_hash
      end
    end
  end
end
