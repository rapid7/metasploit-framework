module Octokit
  class EnterpriseAdminClient

    # Methods for the Enterprise Search Indexing API
    #
    # @see https://developer.github.com/v3/enterprise-admin/search_indexing/
    module SearchIndexing

      # Queue a User or Organization to be indexed
      #
      # @param user [String] A GitHub Enterprise user or organization
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def index_user(user)
        queue_index user
      end
      alias :index_organization :index_user

      # Queue a Repository to be indexed
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def index_repository(repo)
        queue_index Repository.new repo
      end

      # Queue a repository's Issues to be indexed
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def index_repository_issues(repo)
        queue_index "#{Repository.new repo}/issues"
      end

      # Queue a repository's code to be indexed
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def index_repository_code(repo)
        queue_index "#{Repository.new repo}/code"
      end

      # Queue a user's or organization's repositories to be indexed
      #
      # @param user [String] A GitHub Enterprise user or organization
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def index_users_repositories(user)
        queue_index "#{user}/*"
      end
      alias :index_organizations_repositories :index_users_repositories

      # Queue an index of all the issues across all of a user's or
      # organization's repositories
      #
      # @param user [String] A GitHub Enterprise user or organization
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def index_users_repositories_issues(user)
        queue_index "#{user}/*/issues"
      end
      alias :index_organizations_repositories_issues :index_users_repositories_issues

      # Queue an index of all the code contained in all of a user's or
      # organization's repositories
      #
      # @param user [String] A GitHub Enterprise user or organization
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def index_users_repositories_code(user)
        queue_index "#{user}/*/code"
      end
      alias :index_organizations_repositories_code :index_users_repositories_code

      private

      # @private Queue a target for indexing
      #
      # @param target [String] Target to index
      # @return [Sawyer:Resource] Result of the queuing containing `:message`
      def queue_index(target)
        post "staff/indexing_jobs", :target => target
      end
    end

  end
end
