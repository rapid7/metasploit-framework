module Octokit
  class Client

    # Methods for the Traffic API
    #
    # @see https://developer.github.com/v3/repos/traffic/
    module Traffic

      # Get the top 10 referrers over the last 14 days
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] List of referrers and stats
      # @see https://developer.github.com/v3/repos/traffic/#list-referrers
      # @example
      #   @client.top_referrers('octokit/octokit.rb')
      def top_referrers(repo, options = {})
        opts = ensure_api_media_type(:traffic, options)
        get "#{Repository.path repo}/traffic/popular/referrers", opts
      end

      # Get the top 10 popular contents over the last 14 days
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] List of popular contents
      # @see https://developer.github.com/v3/repos/traffic/#list-paths
      # @example
      #   @client.top_paths('octokit/octokit.rb')
      def top_paths(repo, options = {})
        opts = ensure_api_media_type(:traffic, options)
        get "#{Repository.path repo}/traffic/popular/paths", opts
      end

      # Get the total number of views and breakdown per day or week for the
      # last 14 days
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub Repository
      # @option options [String] :per ('day') Views per. <tt>day</tt> or
      #   <tt>week</tt>
      # @return [Sawyer::Resource] Breakdown of view stats
      # @see https://developer.github.com/v3/repos/traffic/#views
      # @example Views per day
      #   @client.views('octokit/octokit.rb')
      # @example Views per week
      #   @client.views('octokit/octokit.rb', per: 'week')
      def views(repo, options = {})
        opts = ensure_api_media_type(:traffic, options)
        get "#{Repository.path repo}/traffic/views", opts
      end

      # Get the total number of clones and breakdown per day or week for the
      # last 14 days
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub Repository
      # @option options [String] :per ('day') Views per. <tt>day</tt> or
      #   <tt>week</tt>
      # @return [Sawyer::Resource] Breakdown of clone stats
      # @see https://developer.github.com/v3/repos/traffic/#clones
      # @example Clones per day
      #   @client.clones('octokit/octokit.rb')
      # @example Clones per week
      #   @client.clones('octokit/octokit.rb', per: 'week')
      def clones(repo, options = {})
        opts = ensure_api_media_type(:traffic, options)
        get "#{Repository.path repo}/traffic/clones", opts
      end

    end
  end
end
