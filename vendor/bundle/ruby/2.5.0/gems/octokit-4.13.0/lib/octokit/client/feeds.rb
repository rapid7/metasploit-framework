module Octokit
  class Client

    # Methods for the Feeds API
    #
    # @see https://developer.github.com/v3/activity/feeds/
    module Feeds

      # List Feeds
      #
      # The feeds returned depend on authentication, see the GitHub API docs
      # for more information.
      #
      # @return [Array<Sawyer::Resource>] list of feeds
      # @see https://developer.github.com/v3/activity/feeds/#list-feeds
      def feeds
        get "feeds"
      end

      # Get a Feed by name
      #
      # @param name [Symbol, String] Name of feed to retrieve.
      # @return [Feed] Parsed feed in the format returned by the configured
      #   parser.
      def feed(name, options = {})
        if rel = feeds._links[name]
          get rel.href, :accept => rel.type, :options => options
        end
      end

    end
  end
end
