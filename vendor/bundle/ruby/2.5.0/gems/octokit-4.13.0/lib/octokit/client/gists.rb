module Octokit
  class Client

    # Methods for the Gists API
    #
    # @see https://developer.github.com/v3/gists/
    module Gists

      # List gists for a user or all public gists
      #
      # @param user [String] An optional user to filter listing
      # @return [Array<Sawyer::Resource>] A list of gists
      # @example Fetch all gists for defunkt
      #   Octokit.gists('defunkt')
      # @example Fetch all public gists
      #   Octokit.gists
      # @see https://developer.github.com/v3/gists/#list-gists
      def gists(user=nil, options = {})
        if user.nil?
          paginate 'gists', options
        else
          paginate "#{User.path user}/gists", options
        end
      end
      alias :list_gists :gists

      # List public gists
      #
      # @return [Array<Sawyer::Resource>] A list of gists
      # @example Fetch all public gists
      #   Octokit.public_gists
      # @see https://developer.github.com/v3/gists/#list-gists
      def public_gists(options = {})
        paginate 'gists/public', options
      end

      # List the authenticated user’s starred gists
      #
      # @return [Array<Sawyer::Resource>] A list of gists
      # @see https://developer.github.com/v3/gists/#list-gists
      def starred_gists(options = {})
        paginate 'gists/starred', options
      end

      # Get a single gist
      #
      # @param gist [String] ID of gist to fetch
      # @option options [String] :sha Specific gist revision SHA
      # @return [Sawyer::Resource] Gist information
      # @see https://developer.github.com/v3/gists/#get-a-single-gist
      # @see https://developer.github.com/v3/gists/#get-a-specific-revision-of-a-gist
      def gist(gist, options = {})
        options = options.dup
        if sha = options.delete(:sha)
          get "gists/#{Gist.new(gist)}/#{sha}", options
        else
          get "gists/#{Gist.new(gist)}", options
        end
      end

      # Create a gist
      #
      # @param options [Hash] Gist information.
      # @option options [String] :description
      # @option options [Boolean] :public Sets gist visibility
      # @option options [Array<Hash>] :files Files that make up this gist. Keys
      #   should be the filename, the value a Hash with a :content key with text
      #   content of the Gist.
      # @return [Sawyer::Resource] Newly created gist info
      # @see https://developer.github.com/v3/gists/#create-a-gist
      def create_gist(options = {})
        post 'gists', options
      end

      # Edit a gist
      #
      # @param options [Hash] Gist information.
      # @option options [String] :description
      # @option options [Hash] :files Files that make up this gist. Keys
      #   should be the filename, the value a Hash with a :content key with text
      #   content of the Gist.
      #
      #   NOTE: All files from the previous version of the
      #   gist are carried over by default if not included in the hash. Deletes
      #   can be performed by including the filename with a null hash.
      # @return
      #   [Sawyer::Resource] Newly created gist info
      # @see https://developer.github.com/v3/gists/#edit-a-gist
      # @example Update a gist
      #   @client.edit_gist('some_id', {
      #     :files => {"boo.md" => {"content" => "updated stuff"}}
      #   })
      def edit_gist(gist, options = {})
        patch "gists/#{Gist.new(gist)}", options
      end

      # List gist commits
      #
      # @param gist [String] Gist ID
      # @return [Array] List of commits to the gist
      # @see https://developer.github.com/v3/gists/#list-gist-commits
      # @example List commits for a gist
      #   @client.gist_commits('some_id')
      def gist_commits(gist, options = {})
        paginate "gists/#{Gist.new(gist)}/commits", options
      end

      #
      # Star a gist
      #
      # @param gist [String] Gist ID
      # @return [Boolean] Indicates if gist is starred successfully
      # @see https://developer.github.com/v3/gists/#star-a-gist
      def star_gist(gist, options = {})
        boolean_from_response :put, "gists/#{Gist.new(gist)}/star", options
      end

      # Unstar a gist
      #
      # @param gist [String] Gist ID
      # @return [Boolean] Indicates if gist is unstarred successfully
      # @see https://developer.github.com/v3/gists/#unstar-a-gist
      def unstar_gist(gist, options = {})
        boolean_from_response :delete, "gists/#{Gist.new(gist)}/star", options
      end

      # Check if a gist is starred
      #
      # @param gist [String] Gist ID
      # @return [Boolean] Indicates if gist is starred
      # @see https://developer.github.com/v3/gists/#check-if-a-gist-is-starred
      def gist_starred?(gist, options = {})
        boolean_from_response :get, "gists/#{Gist.new(gist)}/star", options
      end

      # Fork a gist
      #
      # @param gist [String] Gist ID
      # @return [Sawyer::Resource] Data for the new gist
      # @see https://developer.github.com/v3/gists/#fork-a-gist
      def fork_gist(gist, options = {})
        post "gists/#{Gist.new(gist)}/forks", options
      end

      # List gist forks
      #
      # @param gist [String] Gist ID
      # @return [Array] List of gist forks
      # @see https://developer.github.com/v3/gists/#list-gist-forks
      # @example List gist forks
      #   @client.gist_forks('some-id')
      def gist_forks(gist, options = {})
        paginate "gists/#{Gist.new(gist)}/forks", options
      end

      # Delete a gist
      #
      # @param gist [String] Gist ID
      # @return [Boolean] Indicating success of deletion
      # @see https://developer.github.com/v3/gists/#delete-a-gist
      def delete_gist(gist, options = {})
        boolean_from_response :delete, "gists/#{Gist.new(gist)}", options
      end

      # List gist comments
      #
      # @param gist_id [String] Gist Id.
      # @return [Array<Sawyer::Resource>] Array of hashes representing comments.
      # @see https://developer.github.com/v3/gists/comments/#list-comments-on-a-gist
      # @example
      #   Octokit.gist_comments('3528ae645')
      def gist_comments(gist_id, options = {})
        paginate "gists/#{gist_id}/comments", options
      end

      # Get gist comment
      #
      # @param gist_id [String] Id of the gist.
      # @param gist_comment_id [Integer] Id of the gist comment.
      # @return [Sawyer::Resource] Hash representing gist comment.
      # @see https://developer.github.com/v3/gists/comments/#get-a-single-comment
      # @example
      #   Octokit.gist_comment('208sdaz3', 1451398)
      def gist_comment(gist_id, gist_comment_id, options = {})
        get "gists/#{gist_id}/comments/#{gist_comment_id}", options
      end

      # Create gist comment
      #
      # Requires authenticated client.
      #
      # @param gist_id [String] Id of the gist.
      # @param comment [String] Comment contents.
      # @return [Sawyer::Resource] Hash representing the new comment.
      # @see https://developer.github.com/v3/gists/comments/#create-a-comment
      # @example
      #   @client.create_gist_comment('3528645', 'This is very helpful.')
      def create_gist_comment(gist_id, comment, options = {})
        options = options.merge({:body => comment})
        post "gists/#{gist_id}/comments", options
      end

      # Update gist comment
      #
      # Requires authenticated client
      #
      # @param gist_id [String] Id of the gist.
      # @param gist_comment_id [Integer] Id of the gist comment to update.
      # @param comment [String] Updated comment contents.
      # @return [Sawyer::Resource] Hash representing the updated comment.
      # @see https://developer.github.com/v3/gists/comments/#edit-a-comment
      # @example
      #   @client.update_gist_comment('208sdaz3', '3528645', ':heart:')
      def update_gist_comment(gist_id, gist_comment_id, comment, options = {})
        options = options.merge({:body => comment})
        patch "gists/#{gist_id}/comments/#{gist_comment_id}", options
      end

      # Delete gist comment
      #
      # Requires authenticated client.
      #
      # @param gist_id [String] Id of the gist.
      # @param gist_comment_id [Integer] Id of the gist comment to delete.
      # @return [Boolean] True if comment deleted, false otherwise.
      # @see https://developer.github.com/v3/gists/comments/#delete-a-comment
      # @example
      #   @client.delete_gist_comment('208sdaz3', '586399')
      def delete_gist_comment(gist_id, gist_comment_id, options = {})
        boolean_from_response(:delete, "gists/#{gist_id}/comments/#{gist_comment_id}", options)
      end
    end
  end
end
