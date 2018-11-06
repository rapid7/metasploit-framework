module Octokit
  class Client

    # Method for the Events API
    #
    # @see https://developer.github.com/v3/activity/events/
    # @see https://developer.github.com/v3/issues/events/
    module Events

      # List all public events for GitHub
      #
      # @return [Array<Sawyer::Resource>] A list of all public events from GitHub
      # @see https://developer.github.com/v3/activity/events/#list-public-events
      # @example List all pubilc events
      #   Octokit.public_events
      def public_events(options = {})
        paginate "events", options
      end

      # List all user events
      #
      # @param user [Integer, String] GitHub user login or id.
      # @return [Array<Sawyer::Resource>] A list of all user events
      # @see https://developer.github.com/v3/activity/events/#list-events-performed-by-a-user
      # @example List all user events
      #   Octokit.user_events("sferik")
      def user_events(user, options = {})
        paginate "#{User.path user}/events", options
      end

      # List public user events
      #
      # @param user [Integer, String] GitHub user login or id
      # @return [Array<Sawyer::Resource>] A list of public user events
      # @see https://developer.github.com/v3/activity/events/#list-public-events-performed-by-a-user
      # @example List public user events
      #   Octokit.user_events("sferik")
      def user_public_events(user, options = {})
        paginate "#{User.path user}/events/public", options
      end

      # List events that a user has received
      #
      # @param user [Integer, String] GitHub user login or id
      # @return [Array<Sawyer::Resource>] A list of all user received events
      # @see https://developer.github.com/v3/activity/events/#list-events-that-a-user-has-received
      # @example List all user received events
      #   Octokit.received_events("sferik")
      def received_events(user, options = {})
        paginate "#{User.path user}/received_events", options
      end

      # List public events a user has received
      #
      # @param user [Integer, String] GitHub user login or id
      # @return [Array<Sawyer::Resource>] A list of public user received events
      # @see https://developer.github.com/v3/activity/events/#list-public-events-that-a-user-has-received
      # @example List public user received events
      #   Octokit.received_public_events("sferik")
      def received_public_events(user, options = {})
        paginate "#{User.path user}/received_events/public", options
      end

      # List events for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] A list of events for a repository
      # @see https://developer.github.com/v3/activity/events/#list-repository-events
      # @example List events for a repository
      #   Octokit.repository_events("sferik/rails_admin")
      def repository_events(repo, options = {})
        paginate "#{Repository.path repo}/events", options
      end

      # List public events for a repository's network
      #
      # @param repo [String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] A list of events for a repository's network
      # @see https://developer.github.com/v3/activity/events/#list-public-events-for-a-network-of-repositories
      # @example List events for a repository's network
      #   Octokit.repository_network_events("sferik/rails_admin")
      def repository_network_events(repo, options = {})
        paginate "networks/#{Repository.new(repo)}/events", options
      end

      # List all events for an organization
      #
      # Requires authenticated client.
      #
      # @param org [String] Organization GitHub handle
      # @return [Array<Sawyer::Resource>] List of all events from a GitHub organization
      # @see https://developer.github.com/v3/activity/events/#list-events-for-an-organization
      # @example List events for the lostisland organization
      #   @client.organization_events("lostisland")
      def organization_events(org, options = {})
        paginate "users/#{login}/events/orgs/#{org}", options
      end

      # List an organization's public events
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @return [Array<Sawyer::Resource>] List of public events from a GitHub organization
      # @see https://developer.github.com/v3/activity/events/#list-public-events-for-an-organization
      # @example List public events for GitHub
      #   Octokit.organization_public_events("GitHub")
      def organization_public_events(org, options = {})
        paginate "#{Organization.path org}/events", options
      end

      # Get all Issue Events for a given Repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      #
      # @return [Array<Sawyer::Resource>] Array of all Issue Events for this Repository
      # @see https://developer.github.com/v3/issues/events/#list-events-for-a-repository
      # @see https://developer.github.com/v3/activity/events/#list-issue-events-for-a-repository
      # @example Get all Issue Events for Octokit
      #   Octokit.repository_issue_events("octokit/octokit.rb")
      def repository_issue_events(repo, options = {})
        paginate "#{Repository.path repo}/issues/events", options
      end
      alias :repo_issue_events :repository_issue_events

      # List events for an Issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Issue number
      #
      # @return [Array<Sawyer::Resource>] Array of events for that issue
      # @see https://developer.github.com/v3/issues/events/#list-events-for-an-issue
      # @example List all issues events for issue #38 on octokit/octokit.rb
      #   Octokit.issue_events("octokit/octokit.rb", 38)
      def issue_events(repo, number, options = {})
        paginate "#{Repository.path repo}/issues/#{number}/events", options
      end

      # Get information on a single Issue Event
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Event number
      #
      # @return [Sawyer::Resource] A single Event for an Issue
      # @see https://developer.github.com/v3/issues/events/#get-a-single-event
      # @example Get Event information for ID 3094334 (a pull request was closed)
      #   Octokit.issue_event("octokit/octokit.rb", 3094334)
      def issue_event(repo, number, options = {})
        paginate "#{Repository.path repo}/issues/events/#{number}", options
      end
    end
  end
end
