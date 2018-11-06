module Octokit
  class Client

    # Methods for the Emojis API
    module Emojis

      # List all emojis used on GitHub
      #
      # @return [Sawyer::Resource] A list of all emojis on GitHub
      # @see https://developer.github.com/v3/emojis/#emojis
      # @example List all emojis
      #   Octokit.emojis
      def emojis(options = {})
        get "emojis", options
      end
    end
  end
end
