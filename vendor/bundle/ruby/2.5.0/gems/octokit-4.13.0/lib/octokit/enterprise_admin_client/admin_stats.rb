module Octokit
  class EnterpriseAdminClient

    # Methods for the Enterprise Admin Stats API
    #
    # @see https://developer.github.com/v3/enterprise-admin/admin_stats/
    module AdminStats

      # Get all available stats
      #
      # @return [Sawyer::Resource] All available stats
      # @example Get all available stats
      #   @client.admin_stats
      def admin_stats
        get_admin_stats "all"
      end

      # Get only repository-related stats
      #
      # @return [Sawyer::Resource] Only repository-related stats
      # @example Get only repository-related stats
      #   @client.admin_repository_stats
      def admin_repository_stats
        get_admin_stats "repos"
      end

      # Get only hooks-related stats
      #
      # @return [Sawyer::Resource] Only hooks-related stats
      # @example Get only hooks-related stats
      #   @client.admin_hooks_stats
      def admin_hooks_stats
        get_admin_stats "hooks"
      end

      # Get only pages-related stats
      #
      # @return [Sawyer::Resource] Only pages-related stats
      # @example Get only pages-related stats
      #   @client.admin_pages_stats
      def admin_pages_stats
        get_admin_stats "pages"
      end

      # Get only organization-related stats
      #
      # @return [Sawyer::Resource] Only organization-related stats
      # @example Get only organization-related stats
      #   @client.admin_organization_stats
      def admin_organization_stats
        get_admin_stats "orgs"
      end

      # Get only user-related stats
      #
      # @return [Sawyer::Resource] Only user-related stats
      # @example Get only user-related stats
      #   @client.admin_users_stats
      def admin_users_stats
        get_admin_stats "users"
      end

      # Get only pull request-related stats
      #
      # @return [Sawyer::Resource] Only pull request-related stats
      # @example Get only pull request-related stats
      #   @client.admin_pull_requests_stats
      def admin_pull_requests_stats
        get_admin_stats "pulls"
      end

      # Get only issue-related stats
      #
      # @return [Sawyer::Resource] Only issue-related stats
      # @example Get only issue-related stats
      #   @client.admin_issues_stats
      def admin_issues_stats
        get_admin_stats "issues"
      end

      # Get only milestone-related stats
      #
      # @return [Sawyer::Resource] Only milestone-related stats
      # @example Get only milestone-related stats
      #   @client.admin_milestones_stats
      def admin_milestones_stats
        get_admin_stats "milestones"
      end

      # Get only gist-related stats
      #
      # @return [Sawyer::Resource] Only only gist-related stats
      # @example Get only gist-related stats
      #   @client.admin_gits_stats
      def admin_gists_stats
        get_admin_stats "gists"
      end

      # Get only comment-related stats
      #
      # @return [Sawyer::Resource] Only comment-related stats
      # @example Get only comment-related stats
      #   @client.admin_comments_stats
      def admin_comments_stats
        get_admin_stats "comments"
      end

      private

      # @private Get enterprise stats
      #
      # @param metric [String] The metrics you are looking for
      # @return [Sawyer::Resource] Magical unicorn stats
      def get_admin_stats(metric)
        get "enterprise/stats/#{metric}"
      end
    end

  end
end
