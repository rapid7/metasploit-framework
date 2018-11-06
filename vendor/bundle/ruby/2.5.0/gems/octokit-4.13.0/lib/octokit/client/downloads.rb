module Octokit
  class Client

    # Methods for the Repo Downloads API
    #
    # @see https://developer.github.com/v3/repos/downloads/
    module Downloads

      # List available downloads for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A Github Repository
      # @return [Array] A list of available downloads
      # @deprecated As of December 11th, 2012: https://github.com/blog/1302-goodbye-uploads
      # @see https://developer.github.com/v3/repos/downloads/#list-downloads-for-a-repository
      # @example List all downloads for Github/Hubot
      #   Octokit.downloads("github/hubot")
      def downloads(repo, options={})
        paginate "#{Repository.path repo}/downloads", options
      end
      alias :list_downloads :downloads

      # Get single download for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param id [Integer] ID of the download
      # @return [Sawyer::Resource] A single download from the repository
      # @deprecated As of December 11th, 2012: https://github.com/blog/1302-goodbye-uploads
      # @see https://developer.github.com/v3/repos/downloads/#get-a-single-download
      # @example Get the "Robawt" download from Github/Hubot
      #   Octokit.download("github/hubot")
      def download(repo, id, options={})
        get "#{Repository.path repo}/downloads/#{id}", options
      end

      # Delete a single download for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param id [Integer] ID of the download
      # @deprecated As of December 11th, 2012: https://github.com/blog/1302-goodbye-uploads
      # @see https://developer.github.com/v3/repos/downloads/#delete-a-download
      # @return [Boolean] Status
      # @example Get the "Robawt" download from Github/Hubot
      #   Octokit.delete_download("github/hubot", 1234)
      def delete_download(repo, id, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/downloads/#{id}", options
      end

    end
  end
end
