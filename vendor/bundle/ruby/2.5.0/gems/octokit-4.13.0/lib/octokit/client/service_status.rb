module Octokit
  class Client

    # Methods for the GitHub Status API
    #
    # @see https://status.github.com/api
    module ServiceStatus

      # Root for status API
      # @private
      STATUS_ROOT = 'https://status.github.com/api.json'

      # Returns the current system status
      #
      # @return [Sawyer::Resource] GitHub status
      # @see https://status.github.com/api#api-current-status
      def github_status
        get(STATUS_ROOT).rels[:status].get.data
      end

      # Returns the last human communication, status, and timestamp.
      #
      # @return [Sawyer::Resource] GitHub status last message
      # @see https://status.github.com/api#api-last-message
      def github_status_last_message
        get(STATUS_ROOT).rels[:last_message].get.data
      end

      # Returns the most recent human communications with status and timestamp.
      #
      # @return [Array<Sawyer::Resource>] GitHub status messages
      # @see https://status.github.com/api#api-recent-messages
      def github_status_messages
        get(STATUS_ROOT).rels[:messages].get.data
      end
    end
  end
end
