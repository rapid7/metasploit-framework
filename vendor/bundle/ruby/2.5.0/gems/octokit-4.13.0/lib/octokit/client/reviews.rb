module Octokit
  class Client

    # Methods for the Reviews API
    #
    # @see https://developer.github.com/v3/pulls/reviews/
    module Reviews

      # List reviews on a pull request
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @see https://developer.github.com/v3/pulls/reviews/#list-reviews-on-a-pull-request
      #
      # @example
      #   @client.pull_request_reviews('octokit/octokit.rb', 2)
      #
      # @return [Array<Sawyer::Resource>] Array of Hashes representing the reviews
      def pull_request_reviews(repo, number, options = {})
        paginate "#{Repository.path repo}/pulls/#{number}/reviews", options
      end

      # Get a single review
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @param review [Integer] The id of the review
      # @see https://developer.github.com/v3/pulls/reviews/#get-a-single-review
      #
      # @example
      #   @client.pull_request_review('octokit/octokit.rb', 825, 6505518)
      #
      # @return [Sawyer::Resource] Hash representing the review
      def pull_request_review(repo, number, review, options = {})
        get "#{Repository.path repo}/pulls/#{number}/reviews/#{review}", options
      end

      # Delete a pending review
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @param review [Integer] The id of the review
      # @see https://developer.github.com/v3/pulls/reviews/#delete-a-pending-review
      #
      # @example
      #   @client.delete_pull_request_review('octokit/octokit.rb', 825, 6505518)
      #
      # @return [Sawyer::Resource] Hash representing the deleted review
      def delete_pull_request_review(repo, number, review, options = {})
        delete "#{Repository.path repo}/pulls/#{number}/reviews/#{review}", options
      end

      # Get comments for a single review
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @param review [Integer] The id of the review
      # @see https://developer.github.com/v3/pulls/reviews/#get-comments-for-a-single-review
      #
      # @example
      #   @client.pull_request_review_comments('octokit/octokit.rb', 825, 6505518)
      #
      # @return [Array<Sawyer::Resource>] Array of Hashes representing the review comments
      def pull_request_review_comments(repo, number, review, options = {})
        paginate "#{Repository.path repo}/pulls/#{number}/reviews/#{review}/comments", options
      end

      # Create a pull request review
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @param options [Hash] Method options
      # @option options [String] :event The review action (event) to perform;
      #   can be one of APPROVE, REQUEST_CHANGES, or COMMENT.
      #   If left blank, the review is left PENDING.
      # @option options [String] :body The body text of the pull request review
      # @option options [Array<Hash>] :comments Comments part of the review
      # @option comments [String] :path The path to the file being commented on
      # @option comments [Integer] :position The position in the file to be commented on
      # @option comments [String] :body Body of the comment
      # @see https://developer.github.com/v3/pulls/reviews/#create-a-pull-request-review
      #
      # @example
      #   comments = [
      #     { path: '.travis.yml', position: 10, body: 'ruby-head is under development that is not stable.' },
      #     { path: '.travis.yml', position: 32, body: 'ruby-head is also required in thervm section.' },
      #   ]
      #   options = { event: 'REQUEST_CHANGES', comments: comments }
      #   @client.create_pull_request_review('octokit/octokit.rb', 844, options)
      #
      # @return [Sawyer::Resource>] Hash respresenting the review
      def create_pull_request_review(repo, number, options = {})
        post "#{Repository.path repo}/pulls/#{number}/reviews", options
      end

      # Submit a pull request review
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @param review [Integer] The id of the review
      # @param event [String] The review action (event) to perform; can be one of
      #                       APPROVE, REQUEST_CHANGES, or COMMENT.
      # @param options [Hash] Method options
      # @option options [String] :body The body text of the pull request review
      # @see https://developer.github.com/v3/pulls/reviews/#submit-a-pull-request-review
      #
      # @example
      #   @client.submit_pull_request_review('octokit/octokit.rb', 825, 6505518,
      #                                      'APPROVE', body: 'LGTM!')
      #
      # @return [Sawyer::Resource] Hash respresenting the review
      def submit_pull_request_review(repo, number, review, event, options = {})
        options = options.merge(event: event)
        post "#{Repository.path repo}/pulls/#{number}/reviews/#{review}/events", options
      end

      # Dismiss a pull request review
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @param review [Integer] The id of the review
      # @param message [String] The message for the pull request review dismissal
      # @see https://developer.github.com/v3/pulls/reviews/#dismiss-a-pull-request-review
      #
      # @example
      #   @client.dismiss_pull_request_review('octokit/octokit.rb', 825, 6505518, 'The message.')
      #
      # @return [Sawyer::Resource] Hash representing the dismissed review
      def dismiss_pull_request_review(repo, number, review, message, options = {})
        options = options.merge(message: message)
        put "#{Repository.path repo}/pulls/#{number}/reviews/#{review}/dismissals", options
      end

      # List review requests
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @see https://developer.github.com/v3/pulls/review_requests/#list-review-requests
      #
      # @example
      #   @client.pull_request_review_requests('octokit/octokit.rb', 2)
      #
      # @return [Array<Sawyer::Resource>] Array of Hashes representing the review requests
      def pull_request_review_requests(repo, number, options = {})
        paginate "#{Repository.path repo}/pulls/#{number}/requested_reviewers", options
      end

      # Create a review request
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param number [Integer] Number ID of the pull request
      # @param reviewers [Hash] :reviewers [Array<String>] An array of user logins
      # @param options [Hash] :team_reviewers [Array<String>] An array of team slugs
      # @see https://developer.github.com/v3/pulls/review_requests/#create-a-review-request
      #
      # @example
      #   @client.request_pull_request_review('octokit/octokit.rb', 2, reviewers: ['soudy'])
      #
      # @return [Sawyer::Resource>] Hash respresenting the pull request
      def request_pull_request_review(repo, number, reviewers = {}, options = {})
        # TODO(5.0): remove deprecated behavior
        if reviewers.is_a?(Array)
          octokit_warn(
            "Deprecated: Octokit::Client#request_pull_request_review "\
            "no longer takes a separate :reviewers argument.\n" \
            "Please update your call to pass :reviewers and :team_reviewers as part of the options hash."
          )
          options = options.merge(reviewers: reviewers)
        else
          options = options.merge(reviewers)
        end

        post "#{Repository.path repo}/pulls/#{number}/requested_reviewers", options
      end

      # Delete a review request
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param id [Integer] The id of the pull request
      # @param reviewers [Hash] :reviewers [Array] An array of user logins
      # @param options [Hash] :team_reviewers [Array] An array of team slugs
      #
      # @see https://developer.github.com/v3/pulls/review_requests/#delete-a-review-request
      #
      # @example
      #   options = {
      #     "reviewers" => [ "octocat", "hubot", "other_user" ],
      #     "team_reviewers" => [ "justice-league" ]
      #   }
      #   @client.delete_pull_request_review_request('octokit/octokit.rb', 2, options)
      #
      # @return [Sawyer::Resource>] Hash representing the pull request
      def delete_pull_request_review_request(repo, id, reviewers={}, options = {})
        # TODO(5.0): remove deprecated behavior
        if !reviewers.empty? && !options.empty?
          octokit_warn(
            "Deprecated: Octokit::Client#delete_pull_request_review_request "\
            "no longer takes a separate :reviewers argument.\n" \
            "Please update your call to pass :reviewers and :team_reviewers as part of the options hash."
          )
        end
        # For backwards compatibility, this endpoint can be called with a separate reviewers hash.
        # If not called with a separate hash, then 'reviewers' is, in fact, 'options'.
        options = options.merge(reviewers)
        delete "#{Repository.path repo}/pulls/#{id}/requested_reviewers", options
      end
    end
  end
end
