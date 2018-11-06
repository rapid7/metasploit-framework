module Octokit
  class Client

    # Methods for the Issues API
    #
    # @see https://developer.github.com/v3/issues/
    module Issues

      # List issues for the authenticated user or repository
      #
      # @param repository [Integer, String, Repository, Hash] A GitHub repository.
      # @param options [Sawyer::Resource] A customizable set of options.
      # @option options [Integer] :milestone Milestone number.
      # @option options [String] :state (open) State: <tt>open</tt>, <tt>closed</tt>, or <tt>all</tt>.
      # @option options [String] :assignee User login.
      # @option options [String] :creator User login.
      # @option options [String] :mentioned User login.
      # @option options [String] :labels List of comma separated Label names. Example: <tt>bug,ui,@high</tt>.
      # @option options [String] :sort (created) Sort: <tt>created</tt>, <tt>updated</tt>, or <tt>comments</tt>.
      # @option options [String] :direction (desc) Direction: <tt>asc</tt> or <tt>desc</tt>.
      # @option options [Integer] :page (1) Page number.
      # @return [Array<Sawyer::Resource>] A list of issues for a repository.
      # @see https://developer.github.com/v3/issues/#list-issues-for-a-repository
      # @see https://developer.github.com/v3/issues/#list-issues
      # @example List issues for a repository
      #   Octokit.list_issues("sferik/rails_admin")
      # @example List issues for the authenticated user across repositories
      #   @client = Octokit::Client.new(:login => 'foo', :password => 'bar')
      #   @client.list_issues
      def list_issues(repository = nil, options = {})
        path = repository ? "#{Repository.new(repository).path}/issues" : "issues"
        paginate path, options
      end
      alias :issues :list_issues

      # List all issues across owned and member repositories for the authenticated user
      #
      # @param options [Sawyer::Resource] A customizable set of options.
      # @option options [String] :filter (assigned) State: <tt>assigned</tt>, <tt>created</tt>, <tt>mentioned</tt>, <tt>subscribed</tt> or <tt>closed</tt>.
      # @option options [String] :state (open) State: <tt>open</tt>, <tt>closed</tt>, or <tt>all</tt>.
      # @option options [Array<String>] :labels List of Label names. Example: <tt>['bug', 'ui', '@high']</tt>.
      # @option options [String] :sort (created) Sort: <tt>created</tt>, <tt>updated</tt>, or <tt>comments</tt>.
      # @option options [String] :direction (desc) Direction: <tt>asc</tt> or <tt>desc</tt>.
      # @option options [Integer] :page (1) Page number.
      # @option options [String] :since Timestamp in ISO 8601
      #   format: YYYY-MM-DDTHH:MM:SSZ
      # @return [Array<Sawyer::Resource>] A list of issues for a repository.
      # @see https://developer.github.com/v3/issues/#list-issues
      # @example List issues for the authenticated user across owned and member repositories
      #   @client = Octokit::Client.new(:login => 'foo', :password => 'bar')
      #   @client.user_issues
      def user_issues(options = {})
        paginate 'user/issues', options
      end

      # List all issues for a given organization for the authenticated user
      #
      # @param org [String, Integer] Organization GitHub login or id.
      # @param options [Sawyer::Resource] A customizable set of options.
      # @option options [String] :filter (assigned) State: <tt>assigned</tt>, <tt>created</tt>, <tt>mentioned</tt>, <tt>subscribed</tt> or <tt>closed</tt>.
      # @option options [String] :state (open) State: <tt>open</tt>, <tt>closed</tt>, or <tt>all</tt>.
      # @option options [Array<String>] :labels List of Label names. Example: <tt>['bug', 'ui', '@high']</tt>.
      # @option options [String] :sort (created) Sort: <tt>created</tt>, <tt>updated</tt>, or <tt>comments</tt>.
      # @option options [String] :direction (desc) Direction: <tt>asc</tt> or <tt>desc</tt>.
      # @option options [Integer] :page (1) Page number.
      # @option options [String] :since Timestamp in ISO 8601
      #   format: YYYY-MM-DDTHH:MM:SSZ
      # @return [Array<Sawyer::Resource>] A list of issues.
      # @see https://developer.github.com/v3/issues/#list-issues
      # @example List all issues for a given organization for the authenticated user
      #   @client = Octokit::Client.new(:login => 'foo', :password => 'bar')
      #   @client.org_issues("octokit")
      def org_issues(org, options = {})
        paginate "#{Organization.path org}/issues", options
      end

      # Create an issue for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param title [String] A descriptive title
      # @param body [String] An optional concise description
      # @param options [Hash] A customizable set of options.
      # @option options [String] :assignee User login.
      # @option options [Integer] :milestone Milestone number.
      # @option options [String] :labels List of comma separated Label names. Example: <tt>bug,ui,@high</tt>.
      # @return [Sawyer::Resource] Your newly created issue
      # @see https://developer.github.com/v3/issues/#create-an-issue
      # @example Create a new Issues for a repository
      #   Octokit.create_issue("sferik/rails_admin", 'Updated Docs', 'Added some extra links')
      def create_issue(repo, title, body = nil, options = {})
        options[:labels] = case options[:labels]
                           when String
                             options[:labels].split(",").map(&:strip)
                           when Array
                             options[:labels]
                           else
                             []
                           end
        parameters = { :title => title }
        parameters[:body] = body unless body.nil?
        post "#{Repository.path repo}/issues", options.merge(parameters)
      end
      alias :open_issue :create_issue

      # Get a single issue from a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @return [Sawyer::Resource] The issue you requested, if it exists
      # @see https://developer.github.com/v3/issues/#get-a-single-issue
      # @example Get issue #25 from octokit/octokit.rb
      #   Octokit.issue("octokit/octokit.rb", "25")
      def issue(repo, number, options = {})
        get "#{Repository.path repo}/issues/#{number}", options
      end

      # Close an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @param options [Hash] A customizable set of options.
      # @option options [String] :assignee User login.
      # @option options [Integer] :milestone Milestone number.
      # @option options [Array<String>] :labels List of Label names. Example: <tt>['bug', 'ui', '@high']</tt>.
      # @return [Sawyer::Resource] The updated Issue
      # @see https://developer.github.com/v3/issues/#edit-an-issue
      # @example Close Issue #25 from octokit/octokit.rb
      #   Octokit.close_issue("octokit/octokit.rb", "25")
      def close_issue(repo, number, options = {})
        patch "#{Repository.path repo}/issues/#{number}", options.merge({:state => "closed"})
      end

      # Reopen an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @param options [Hash] A customizable set of options.
      # @option options [String] :assignee User login.
      # @option options [Integer] :milestone Milestone number.
      # @option options [Array<String>] :labels List of Label names. Example: <tt>['bug', 'ui', '@high']</tt>.
      # @return [Sawyer::Resource] The updated Issue
      # @see https://developer.github.com/v3/issues/#edit-an-issue
      # @example Reopen Issue #25 from octokit/octokit.rb
      #   Octokit.reopen_issue("octokit/octokit.rb", "25")
      def reopen_issue(repo, number, options = {})
        patch "#{Repository.path repo}/issues/#{number}", options.merge({:state => "open"})
      end

      # Lock an issue's conversation, limiting it to collaborators
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/issues/#lock-an-issue
      # @example Lock Issue #25 from octokit/octokit.rb
      #   Octokit.lock_issue("octokit/octokit.rb", "25")
      def lock_issue(repo, number, options = {})
        boolean_from_response :put, "#{Repository.path repo}/issues/#{number}/lock", options
      end

      # Unlock an issue's conversation, opening it to all viewers
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/issues/#unlock-an-issue
      # @example Unlock Issue #25 from octokit/octokit.rb
      #   Octokit.close_issue("octokit/octokit.rb", "25")
      def unlock_issue(repo, number, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/issues/#{number}/lock", options
      end

      # Update an issue
      #
      # @overload update_issue(repo, number, title, body, options)
      #   @param repo [Integer, String, Repository, Hash] A GitHub repository
      #   @param number [Integer] Number ID of the issue
      #   @param title [String] Updated title for the issue
      #   @param body [String] Updated body of the issue
      #   @param options [Hash] A customizable set of options.
      #   @option options [String] :assignee User login.
      #   @option options [Integer] :milestone Milestone number.
      #   @option options [String] :labels List of comma separated Label names. Example: <tt>bug,ui,@high</tt>.
      #   @option options [String] :state State of the issue. <tt>open</tt> or <tt>closed</tt>
      #
      # @overload update_issue(repo, number, options)
      #   @param repo [Integer, String, Repository, Hash] A GitHub repository
      #   @param number [Integer] Number ID of the issue
      #   @param options [Hash] A customizable set of options.
      #   @option options [String] :title Updated title for the issue
      #   @option options [String] :body Updated body of the issue
      #   @option options [String] :assignee User login.
      #   @option options [Integer] :milestone Milestone number.
      # @option options [Array<String>] :labels List of Label names. Example: <tt>['bug', 'ui', '@high']</tt>.
      #   @option options [String] :state State of the issue. <tt>open</tt> or <tt>closed</tt>
      # @return [Sawyer::Resource] The updated Issue
      # @see https://developer.github.com/v3/issues/#edit-an-issue
      #
      # @example Change the title of Issue #25
      #   Octokit.update_issue("octokit/octokit.rb", "25", "A new title", "the same body")
      #
      # @example Change only the assignee of Issue #25
      #   Octokit.update_issue("octokit/octokit.rb", "25", :assignee => "pengwynn")
      def update_issue(repo, number, *args)
        arguments = Arguments.new(args)
        opts = arguments.options

        if arguments.length > 0
          opts[:title] = arguments.shift
          opts[:body] = arguments.shift
        end

        patch "#{Repository.path repo}/issues/#{number}", opts
      end

      # Get all comments attached to issues for the repository
      #
      # By default, Issue Comments are ordered by ascending ID.
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param options [Hash] Optional parameters
      # @option options [String] :sort created or updated
      # @option options [String] :direction asc or desc. Ignored without sort
      #   parameter.
      # @option options [String] :since Timestamp in ISO 8601
      #   format: YYYY-MM-DDTHH:MM:SSZ
      #
      # @return [Array<Sawyer::Resource>] List of issues comments.
      #
      # @see https://developer.github.com/v3/issues/comments/#list-comments-in-a-repository
      #
      # @example Get the comments for issues in the octokit repository
      #   @client.issues_comments("octokit/octokit.rb")
      #
      # @example Get issues comments, sort by updated descending since a time
      #   @client.issues_comments("octokit/octokit.rb", {
      #     :sort => 'desc',
      #     :direction => 'asc',
      #     :since => '2010-05-04T23:45:02Z'
      #   })
      def issues_comments(repo, options = {})
        paginate "#{Repository.path repo}/issues/comments", options
      end

      # Get all comments attached to an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @return [Array<Sawyer::Resource>] Array of comments that belong to an issue
      # @see https://developer.github.com/v3/issues/comments/#list-comments-on-an-issue
      # @example Get comments for issue #25 from octokit/octokit.rb
      #   Octokit.issue_comments("octokit/octokit.rb", "25")
      def issue_comments(repo, number, options = {})
        paginate "#{Repository.path repo}/issues/#{number}/comments", options
      end

      # Get a single comment attached to an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the comment
      # @return [Sawyer::Resource] The specific comment in question
      # @see https://developer.github.com/v3/issues/comments/#get-a-single-comment
      # @example Get comment #1194549 from an issue on octokit/octokit.rb
      #   Octokit.issue_comment("octokit/octokit.rb", 1194549)
      def issue_comment(repo, number, options = {})
        paginate "#{Repository.path repo}/issues/comments/#{number}", options
      end

      # Add a comment to an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Issue number
      # @param comment [String] Comment to be added
      # @return [Sawyer::Resource] Comment
      # @see https://developer.github.com/v3/issues/comments/#create-a-comment
      # @example Add the comment "Almost to v1" to Issue #23 on octokit/octokit.rb
      #   Octokit.add_comment("octokit/octokit.rb", 23, "Almost to v1")
      def add_comment(repo, number, comment, options = {})
        post "#{Repository.path repo}/issues/#{number}/comments", options.merge({:body => comment})
      end

      # Update a single comment on an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Comment number
      # @param comment [String] Body of the comment which will replace the existing body.
      # @return [Sawyer::Resource] Comment
      # @see https://developer.github.com/v3/issues/comments/#edit-a-comment
      # @example Update the comment #1194549 with body "I've started this on my 25-issue-comments-v3 fork" on an issue on octokit/octokit.rb
      #   Octokit.update_comment("octokit/octokit.rb", 1194549, "Almost to v1, added this on my fork")
      def update_comment(repo, number, comment, options = {})
        patch "#{Repository.path repo}/issues/comments/#{number}", options.merge({:body => comment})
      end

      # Delete a single comment
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Comment number
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/issues/comments/#delete-a-comment
      # @example Delete the comment #1194549 on an issue on octokit/octokit.rb
      #   Octokit.delete_comment("octokit/octokit.rb", 1194549)
      def delete_comment(repo, number, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/issues/comments/#{number}", options
      end

      # Get the timeline for an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the comment
      # @return [Sawyer::Resource] The timeline for this issue
      # @see https://developer.github.com/v3/issues/timeline/
      # @example Get timeline for issue #1435 on octokit/octokit.rb
      #   Octokit.issue_timeline("octokit/octokit.rb", 1435)
      def issue_timeline(repo, number, options = {})
        options = ensure_api_media_type(:issue_timelines, options)
        paginate "#{Repository.path repo}/issues/#{number}/timeline", options
      end

      # Lists the available assignees for issues in a repository.
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] List of GitHub users.
      # @see https://developer.github.com/v3/issues/assignees/#list-assignees
      # @example Get available assignees on repository octokit/octokit.rb
      #   Octokit.list_assignees("octokit/octokit.rb")
      def list_assignees(repo, options = {})
        paginate "#{Repository.path repo}/assignees", options
      end

      # Add assignees to an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Issue number
      # @param assignees [Array] Assignees to be added
      # @return [Sawyer::Resource] Issue
      # @see https://developer.github.com/v3/issues/assignees/#add-assignees-to-an-issue
      # @example Add assignees "pengwynn" and "joeyw" to Issue #23 on octokit/octokit.rb
      #   Octokit.add_assignees("octokit/octokit.rb", 23, ["pengwynn", "joeyw"])
      def add_assignees(repo, number, assignees, options = {})
        post "#{Repository.path repo}/issues/#{number}/assignees", options.merge({:assignees => assignees})
      end

      # Remove assignees from an issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Issue number
      # @param assignees [Array] Assignees to be removed
      # @param options [Hash] Header params for request
      # @return [Sawyer::Resource] Issue
      # @see https://developer.github.com/v3/issues/assignees/#remove-assignees-from-an-issue
      # @example Remove assignees "pengwynn" and "joeyw" from Issue #23 on octokit/octokit.rb
      #   Octokit.remove_assignees("octokit/octokit.rb", 23, ["pengwynn", "joeyw"])
      #
      # @example Remove assignees "pengwynn" from Issue #23 on octokit/octokit.rb
      #   Octokit.remove_assignees("octokit/octokit.rb", 23, ["pengwynn"],
      #     :accept => "application/vnd.github.v3+json")
      def remove_assignees(repo, number, assignees, options = {})
        delete "#{Repository.path repo}/issues/#{number}/assignees", options.merge({:assignees => assignees})
      end
    end
  end
end
