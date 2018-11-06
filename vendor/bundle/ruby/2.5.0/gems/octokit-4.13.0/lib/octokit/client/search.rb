module Octokit
  class Client

    # Methods for the Search API
    #
    # @see https://developer.github.com/v3/search/
    module Search

      # Search code
      #
      # @param query [String] Search term and qualifiers
      # @param options [Hash] Sort and pagination options
      # @option options [String] :sort Sort field
      # @option options [String] :order Sort order (asc or desc)
      # @option options [Integer] :page Page of paginated results
      # @option options [Integer] :per_page Number of items per page
      # @return [Sawyer::Resource] Search results object
      # @see https://developer.github.com/v3/search/#search-code
      def search_code(query, options = {})
        search "search/code", query, options
      end

      # Search commits
      #
      # @param query [String] Search terms and qualifiers
      # @param options [Hash] Sort and pagination options
      # @option options [String] :sort Sort field
      # @option options [String] :order Sort order (asc or desc)
      # @option options [Integer] :page Page of paginated results
      # @option options [Integer] :per_page Number of items per page
      # @return [Sawyer::Resource] Search results object
      # @see https://developer.github.com/v3/search/#search-commits
      def search_commits(query, options = {})
        options = ensure_api_media_type(:commit_search, options)
        search "search/commits", query, options
      end

      # Search issues
      #
      # @param query [String] Search term and qualifiers
      # @param options [Hash] Sort and pagination options
      # @option options [String] :sort Sort field
      # @option options [String] :order Sort order (asc or desc)
      # @option options [Integer] :page Page of paginated results
      # @option options [Integer] :per_page Number of items per page
      # @return [Sawyer::Resource] Search results object
      # @see https://developer.github.com/v3/search/#search-issues
      def search_issues(query, options = {})
        search "search/issues", query, options
      end

      # Search repositories
      #
      # @param query [String] Search term and qualifiers
      # @param options [Hash] Sort and pagination options
      # @option options [String] :sort Sort field
      # @option options [String] :order Sort order (asc or desc)
      # @option options [Integer] :page Page of paginated results
      # @option options [Integer] :per_page Number of items per page
      # @return [Sawyer::Resource] Search results object
      # @see https://developer.github.com/v3/search/#search-repositories
      def search_repositories(query, options = {})
        search "search/repositories", query, options
      end
      alias :search_repos :search_repositories

      # Search users
      #
      # @param query [String] Search term and qualifiers
      # @param options [Hash] Sort and pagination options
      # @option options [String] :sort Sort field
      # @option options [String] :order Sort order (asc or desc)
      # @option options [Integer] :page Page of paginated results
      # @option options [Integer] :per_page Number of items per page
      # @return [Sawyer::Resource] Search results object
      # @see https://developer.github.com/v3/search/#search-users
      def search_users(query, options = {})
        search "search/users", query, options
      end

      private

      def search(path, query, options = {})
        opts = options.merge(:q => query)
        paginate(path, opts) do |data, last_response|
          data.items.concat last_response.data.items
        end
      end
    end
  end
end
