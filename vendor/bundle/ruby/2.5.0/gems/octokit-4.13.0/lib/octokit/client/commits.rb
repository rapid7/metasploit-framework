require 'date'

module Octokit
  class Client

    # Methods for the Commits API
    #
    # @see https://developer.github.com/v3/repos/commits/
    module Commits

      # List commits
      #
      # @overload commits(repo, sha_or_branch, options = {})
      #   @deprecated
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param sha_or_branch [String] A commit SHA or branch name
      #   @param options [String] :sha Commit SHA or branch name from which to start the list
      # @overload commits(repo, options = {})
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param options [String] :sha Commit SHA or branch name from which to start the list
      # @return [Array<Sawyer::Resource>] An array of hashes representing commits
      # @see https://developer.github.com/v3/repos/commits/#list-commits-on-a-repository
      def commits(*args)
        arguments = Octokit::RepoArguments.new(args)
        sha_or_branch = arguments.pop
        if sha_or_branch
          arguments.options[:sha] = sha_or_branch
        end
        paginate "#{Repository.new(arguments.repo).path}/commits", arguments.options
      end
      alias :list_commits :commits

      # Get commits after a specified date
      #
      # @overload commits_since(repo, date, options = {})
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param date [String] Date on which we want to compare
      #   @param options [String] :sha Commit SHA or branch name from which to start the list
      # @overload commits_since(repo, date, sha_or_branch, options = {})
      #   @deprecated
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param date [String] Date on which we want to compare
      #   @param sha_or_branch [String] A commit SHA or branch name
      #   @param options [String] :sha Commit SHA or branch name from which to start the list
      # @return [Array<Sawyer::Resource>] An array of hashes representing commits
      # @see https://developer.github.com/v3/repos/commits/#list-commits-on-a-repository
      # @example
      #   Octokit.commits_since('octokit/octokit.rb', '2012-10-01')
      def commits_since(*args)
        arguments = Octokit::RepoArguments.new(args)
        date   = parse_date(arguments.shift)
        params = arguments.options
        params.merge!(:since => iso8601(date))
        sha_or_branch = arguments.pop
        if sha_or_branch
          params[:sha] = sha_or_branch
        end
        commits(arguments.repo, params)
      end

      # Get commits before a specified date
      #
      # @overload commits_before(repo, date, options = {})
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param date [String] Date on which we want to compare
      # @overload commits_before(repo, date, sha_or_branch, options = {})
      #   @deprecated
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param date [String] Date on which we want to compare
      #   @param sha_or_branch [String] Commit SHA or branch name from which to start the list
      # @return [Array<Sawyer::Resource>] An array of hashes representing commits
      # @see https://developer.github.com/v3/repos/commits/#list-commits-on-a-repository
      # @example
      #   Octokit.commits_before('octokit/octokit.rb', '2012-10-01')
      def commits_before(*args)
        arguments = Octokit::RepoArguments.new(args)
        date   = parse_date(arguments.shift)
        params = arguments.options
        params.merge!(:until => iso8601(date))
        sha_or_branch = arguments.pop
        if sha_or_branch
          params[:sha] = sha_or_branch
        end
        commits(arguments.repo, params)
      end

      # Get commits on a specified date
      #
      # @overload commits_on(repo, date, options = {})
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param date [String] Date on which we want to compare
      # @overload commits_on(repo, date, sha_or_branch, options = {})
      #   @deprecated
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param date [String] Date on which we want to compare
      #   @param sha_or_branch [String] Commit SHA or branch name from which to start the list
      # @return [Array<Sawyer::Resource>] An array of hashes representing commits
      # @see https://developer.github.com/v3/repos/commits/#list-commits-on-a-repository
      # @example
      #   Octokit.commits_on('octokit/octokit.rb', '2012-10-01')
      def commits_on(*args)
        arguments = Octokit::RepoArguments.new(args)
        date   = parse_date(arguments.shift)
        params = arguments.options
        end_date = date + 1
        params.merge!(:since => iso8601(date), :until => iso8601(end_date))
        sha_or_branch = arguments.pop
        if sha_or_branch
          params[:sha] = sha_or_branch
        end
        commits(arguments.repo, params)
      end

      # Get commits made between two nominated dates
      #
      # @overload commits_between(repo, start_date, end_date, options = {})
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param start_date [String] Start Date on which we want to compare
      #   @param end_date [String] End Date on which we want to compare
      # @overload commits_between(repo, start_date, end_date, sha_or_branch, options = {})
      #   @deprecated
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository
      #   @param start_date [String] Start Date on which we want to compare
      #   @param end_date [String] End Date on which we want to compare
      #   @param sha_or_branch [String] Commit SHA or branch name from which to start the list
      # @return [Array<Sawyer::Resource>] An array of hashes representing commits
      # @see https://developer.github.com/v3/repos/commits/#list-commits-on-a-repository
      # @example
      #   Octokit.commits_between('octokit/octokit.rb', '2012-10-01', '2012-11-01')
      def commits_between(*args)
        arguments = Octokit::RepoArguments.new(args)
        date       = parse_date(arguments.shift)
        end_date   = parse_date(arguments.shift)
        raise ArgumentError, "Start date #{date} does not precede #{end_date}" if date > end_date

        params = arguments.options
        params.merge!(:since => iso8601(date), :until => iso8601(end_date))
        sha_or_branch = arguments.pop
        if sha_or_branch
          params[:sha] = sha_or_branch
        end
        commits(arguments.repo, params)
      end

      # Get a single commit
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param sha [String] The SHA of the commit to fetch
      # @return [Sawyer::Resource] A hash representing the commit
      # @see https://developer.github.com/v3/repos/commits/#get-a-single-commit
      def commit(repo, sha, options = {})
        get "#{Repository.path repo}/commits/#{sha}", options
      end

      # Get a detailed git commit
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param sha [String] The SHA of the commit to fetch
      # @return [Sawyer::Resource] A hash representing the commit
      # @see https://developer.github.com/v3/git/commits/#get-a-commit
      def git_commit(repo, sha, options = {})
        get "#{Repository.path repo}/git/commits/#{sha}", options
      end

      # Create a commit
      #
      # Optionally pass <tt>author</tt> and <tt>committer</tt> hashes in <tt>options</tt>
      # if you'd like manual control over those parameters. If absent, details will be
      # inferred from the authenticated user. See <a href="http://developer.github.com/v3/git/commits/">GitHub's documentation</a>
      # for details about how to format committer identities.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param message [String] The commit message
      # @param tree [String] The SHA of the tree object the new commit will point to
      # @param parents [String, Array] One SHA (for a normal commit) or an array of SHAs (for a merge) of the new commit's parent commits. If ommitted or empty, a root commit will be created
      # @return [Sawyer::Resource] A hash representing the new commit
      # @see https://developer.github.com/v3/git/commits/#create-a-commit
      # @example Create a commit
      #   commit = Octokit.create_commit("octocat/Hello-World", "My commit message", "827efc6d56897b048c772eb4087f854f46256132", "7d1b31e74ee336d15cbd21741bc88a537ed063a0")
      #   commit.sha # => "7638417db6d59f3c431d3e1f261cc637155684cd"
      #   commit.tree.sha # => "827efc6d56897b048c772eb4087f854f46256132"
      #   commit.message # => "My commit message"
      #   commit.committer # => { "name" => "Wynn Netherland", "email" => "wynn@github.com", ... }
      def create_commit(repo, message, tree, parents=nil, options = {})
        params = { :message => message, :tree => tree }
        params[:parents] = [parents].flatten if parents
        post "#{Repository.path repo}/git/commits", options.merge(params)
      end

      # Compare two commits
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param start [String] The sha of the starting commit
      # @param endd [String] The sha of the ending commit
      # @return [Sawyer::Resource] A hash representing the comparison
      # @see https://developer.github.com/v3/repos/commits/#compare-two-commits
      def compare(repo, start, endd, options = {})
        get "#{Repository.path repo}/compare/#{start}...#{endd}", options
      end

      # Merge a branch or sha
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param base [String] The name of the base branch to merge into
      # @param head [String] The branch or SHA1 to merge
      # @option options [String] :commit_message The commit message for the merge
      # @return [Sawyer::Resource] A hash representing the comparison
      # @see https://developer.github.com/v3/repos/merging/#perform-a-merge
      def merge(repo, base, head, options = {})
        params = {
          :base => base,
          :head => head
        }.merge(options)
        post "#{Repository.path repo}/merges", params
      end

      protected

      def iso8601(date)
        if date.respond_to?(:iso8601)
          date.iso8601
        else
          date.strftime("%Y-%m-%dT%H:%M:%S%Z")
        end
      end

      # Parses the given string representation of a date, throwing a meaningful exception
      # (containing the date that failed to parse) in case of failure.
      #
      # @param date [String] String representation of a date
      # @return [DateTime]
      def parse_date(date)
        date = DateTime.parse(date.to_s)
      rescue ArgumentError
        raise ArgumentError, "#{date} is not a valid date"
      end
    end
  end
end
