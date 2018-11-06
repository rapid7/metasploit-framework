module Octokit
  class Client

    # Methods for the Meta API
    #
    # @see https://developer.github.com/v3/meta/
    module Meta

      # Get meta information about GitHub.com, the service.
      # @see https://developer.github.com/v3/meta/#meta
      # @return [Sawyer::Resource] Hash with meta information.
      # @example Get GitHub meta information
      #   @client.github_meta
      def meta(options = {})
        get "meta", options
      end
      alias :github_meta :meta

    end
  end
end
