module Octokit
  class Client

    # Methods for the Community Profile API
    #
    # @see https://developer.github.com/v3/repos/community/
    module CommunityProfile

      # Get community profile metrics for a repository
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Sawyer::Resource] Community profile metrics
      # @see https://developer.github.com/v3/repos/community/#retrieve-community-profile-metrics
      # @example Get community profile metrics for octokit/octokit.rb
      #   @client.community_profile('octokit/octokit.rb')
      def community_profile(repo, options = {})
        options = ensure_api_media_type(:community_profile, options)
        get "#{Repository.path repo}/community/profile", options
      end
    end
  end
end
