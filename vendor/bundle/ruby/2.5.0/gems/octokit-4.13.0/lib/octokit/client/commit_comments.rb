module Octokit
  class Client

    # Methods for the Commit Comments API
    #
    # @see https://developer.github.com/v3/repos/comments/
    module CommitComments

      # List all commit comments
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Array] List of commit comments
      # @see https://developer.github.com/v3/repos/comments/#list-commit-comments-for-a-repository
      def list_commit_comments(repo, options = {})
        paginate "#{Repository.path repo}/comments", options
      end

      # List comments for a single commit
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param sha [String] The SHA of the commit whose comments will be fetched
      # @return [Array]  List of commit comments
      # @see https://developer.github.com/v3/repos/comments/#list-comments-for-a-single-commit
      def commit_comments(repo, sha, options = {})
        paginate "#{Repository.path repo}/commits/#{sha}/comments", options
      end

      # Get a single commit comment
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param id [String] The ID of the comment to fetch
      # @return [Sawyer::Resource] Commit comment
      # @see https://developer.github.com/v3/repos/comments/#get-a-single-commit-comment
      def commit_comment(repo, id, options = {})
        get "#{Repository.path repo}/comments/#{id}", options
      end

      # Create a commit comment
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param sha [String] Sha of the commit to comment on
      # @param body [String] Message
      # @param path [String] Relative path of file to comment on
      # @param line [Integer] Line number in the file to comment on
      # @param position [Integer] Line index in the diff to comment on
      # @return [Sawyer::Resource] Commit comment
      # @see https://developer.github.com/v3/repos/comments/#create-a-commit-comment
      # @example Create a commit comment
      #   comment = Octokit.create_commit_comment("octocat/Hello-World", "827efc6d56897b048c772eb4087f854f46256132", "My comment message", "README.md", 10, 1)
      #   comment.commit_id # => "827efc6d56897b048c772eb4087f854f46256132"
      #   comment.id # => 54321
      #   comment.body # => "My comment message"
      #   comment.path # => "README.md"
      #   comment.line # => 10
      #   comment.position # => 1
      def create_commit_comment(repo, sha, body, path=nil, line=nil, position=nil, options = {})
        params = {
          :body => body,
          :path => path,
          :line => line,
          :position => position
        }
        post "#{Repository.path repo}/commits/#{sha}/comments", options.merge(params)
      end

      # Update a commit comment
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param id [String] The ID of the comment to update
      # @param body [String] Message
      # @return [Sawyer::Resource] Updated commit comment
      # @see https://developer.github.com/v3/repos/comments/#update-a-commit-comment
      # @example Update a commit comment
      #   comment = Octokit.update_commit_comment("octocat/Hello-World", "860296", "Updated commit comment")
      #   comment.id # => 860296
      #   comment.body # => "Updated commit comment"
      def update_commit_comment(repo, id, body, options = {})
        params = {
          :body => body
        }
        patch "#{Repository.path repo}/comments/#{id}", options.merge(params)
      end

      # Delete a commit comment
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param id [String] The ID of the comment to delete
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/repos/comments/#delete-a-commit-comment
      def delete_commit_comment(repo, id, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/comments/#{id}", options
      end
    end
  end
end
