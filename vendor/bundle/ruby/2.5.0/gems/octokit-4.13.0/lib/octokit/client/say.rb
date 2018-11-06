module Octokit
  class Client

    # Methods for the unpublished Octocat API
    module Say

      # Return a nifty ASCII Octocat with GitHub wisdom
      # or your own
      #
      # @return [String]
      def say(text = nil, options = {})
        options[:s] = text if text
        get "octocat", options
      end
      alias :octocat :say

    end
  end
end
