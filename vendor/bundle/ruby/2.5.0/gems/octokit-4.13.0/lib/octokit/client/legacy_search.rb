module Octokit
  class Client

    # Methods for the Legacy Search API
    #
    # @see https://developer.github.com/v3/search/
    module LegacySearch

      # Legacy repository search
      #
      # @see https://developer.github.com/v3/search/#search-repositories
      # @param q [String] Search keyword
      # @return [Array<Sawyer::Resource>] List of repositories found
      def legacy_search_repositories(q, options = {})
        get("legacy/repos/search/#{q}", options)['repositories']
      end

      # Legacy search issues within a repository
      #
      # @param repo [String, Repository, Hash] A GitHub repository
      # @param search_term [String] The term to search for
      # @param state [String] :state (open) <tt>open</tt> or <tt>closed</tt>.
      # @return [Array<Sawyer::Resource>] A list of issues matching the search term and state
      # @example Search for 'test' in the open issues for sferik/rails_admin
      #   Octokit.search_issues("sferik/rails_admin", 'test', 'open')
      def legacy_search_issues(repo, search_term, state='open', options = {})
        get("legacy/issues/search/#{Repository.new(repo)}/#{state}/#{search_term}", options)['issues']
      end

      # Search for user.
      #
      # @param search [String] User to search for.
      # @return [Array<Sawyer::Resource>] Array of hashes representing users.
      # @see https://developer.github.com/v3/search/#search-users
      # @example
      #   Octokit.search_users('pengwynn')
      def legacy_search_users(search, options = {})
        get("legacy/user/search/#{search}", options)['users']
      end
    end
  end
end
