module Octokit
  class Client

    # Methods for the Repositories API
    #
    # @see https://developer.github.com/v3/repos/
    module Repositories

      # Check if a repository exists
      #
      # @see https://developer.github.com/v3/repos/#get
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Sawyer::Resource] if a repository exists, false otherwise
      def repository?(repo, options = {})
        !!repository(repo, options)
      rescue Octokit::InvalidRepository
        false
      rescue Octokit::NotFound
        false
      end

      # Get a single repository
      #
      # @see https://developer.github.com/v3/repos/#get
      # @see https://developer.github.com/v3/licenses/#get-a-repositorys-license
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Sawyer::Resource] Repository information
      def repository(repo, options = {})
        get Repository.path(repo), options
      end
      alias :repo :repository

      # Edit a repository
      #
      # @see https://developer.github.com/v3/repos/#edit
      # @param repo [String, Hash, Repository] A GitHub repository
      # @param options [Hash] Repository information to update
      # @option options [String] :name Name of the repo
      # @option options [String] :description Description of the repo
      # @option options [String] :homepage Home page of the repo
      # @option options [String] :private `true` makes the repository private, and `false` makes it public.
      # @option options [String] :has_issues `true` enables issues for this repo, `false` disables issues.
      # @option options [String] :has_wiki `true` enables wiki for this repo, `false` disables wiki.
      # @option options [String] :has_downloads `true` enables downloads for this repo, `false` disables downloads.
      # @option options [String] :default_branch Update the default branch for this repository.
      # @return [Sawyer::Resource] Repository information
      def edit_repository(repo, options = {})
        repo = Repository.new(repo)
        options[:name] ||= repo.name
        patch "repos/#{repo}", options
      end
      alias :edit :edit_repository
      alias :update_repository :edit_repository
      alias :update :edit_repository

      # List user repositories
      #
      # If user is not supplied, repositories for the current
      #   authenticated user are returned.
      #
      # @note If the user provided is a GitHub organization, only the
      #   organization's public repositories will be listed. For retrieving
      #   organization repositories the {Organizations#organization_repositories}
      #   method should be used instead.
      # @see https://developer.github.com/v3/repos/#list-your-repositories
      # @see https://developer.github.com/v3/repos/#list-user-repositories
      # @param user [Integer, String] Optional GitHub user login or id for which
      #   to list repos.
      # @return [Array<Sawyer::Resource>] List of repositories
      def repositories(user=nil, options = {})
        paginate "#{User.path user}/repos", options
      end
      alias :list_repositories :repositories
      alias :list_repos :repositories
      alias :repos :repositories

      # List all repositories
      #
      # This provides a dump of every repository, in the order that they were
      # created.
      #
      # @see https://developer.github.com/v3/repos/#list-all-public-repositories
      #
      # @param options [Hash] Optional options
      # @option options [Integer] :since The integer ID of the last Repository
      #   that you’ve seen.
      # @return [Array<Sawyer::Resource>] List of repositories.
      def all_repositories(options = {})
        paginate 'repositories', options
      end

      # Star a repository
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Boolean] `true` if successfully starred
      # @see https://developer.github.com/v3/activity/starring/#star-a-repository
      def star(repo, options = {})
        boolean_from_response :put, "user/starred/#{Repository.new(repo)}", options
      end

      # Unstar a repository
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Boolean] `true` if successfully unstarred
      # @see https://developer.github.com/v3/activity/starring/#unstar-a-repository
      def unstar(repo, options = {})
        boolean_from_response :delete, "user/starred/#{Repository.new(repo)}", options
      end

      # Watch a repository
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Boolean] `true` if successfully watched
      # @deprecated Use #star instead
      # @see https://developer.github.com/v3/activity/watching/#watch-a-repository-legacy
      def watch(repo, options = {})
        boolean_from_response :put, "user/watched/#{Repository.new(repo)}", options
      end

      # Unwatch a repository
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Boolean] `true` if successfully unwatched
      # @deprecated Use #unstar instead
      # @see https://developer.github.com/v3/activity/watching/#stop-watching-a-repository-legacy
      def unwatch(repo, options = {})
        boolean_from_response :delete, "user/watched/#{Repository.new(repo)}", options
      end

      # Fork a repository
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Sawyer::Resource] Repository info for the new fork
      # @see https://developer.github.com/v3/repos/forks/#create-a-fork
      def fork(repo, options = {})
        post "#{Repository.path repo}/forks", options
      end

      # Create a repository for a user or organization
      #
      # @param name [String] Name of the new repo
      # @option options [String] :description Description of the repo
      # @option options [String] :homepage Home page of the repo
      # @option options [String] :private `true` makes the repository private, and `false` makes it public.
      # @option options [String] :has_issues `true` enables issues for this repo, `false` disables issues.
      # @option options [String] :has_wiki `true` enables wiki for this repo, `false` disables wiki.
      # @option options [String] :has_downloads `true` enables downloads for this repo, `false` disables downloads.
      # @option options [String] :organization Short name for the org under which to create the repo.
      # @option options [Integer] :team_id The id of the team that will be granted access to this repository. This is only valid when creating a repo in an organization.
      # @option options [Boolean] :auto_init `true` to create an initial commit with empty README. Default is `false`.
      # @option options [String] :gitignore_template Desired language or platform .gitignore template to apply. Ignored if auto_init parameter is not provided.
      # @return [Sawyer::Resource] Repository info for the new repository
      # @see https://developer.github.com/v3/repos/#create
      def create_repository(name, options = {})
        opts = options.dup
        organization = opts.delete :organization
        opts.merge! :name => name

        if organization.nil?
          post 'user/repos', opts
        else
          post "#{Organization.path organization}/repos", opts
        end
      end
      alias :create_repo :create_repository
      alias :create :create_repository

      # Delete repository
      #
      # Note: If OAuth is used, 'delete_repo' scope is required
      #
      # @see https://developer.github.com/v3/repos/#delete-a-repository
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Boolean] `true` if repository was deleted
      def delete_repository(repo, options = {})
        boolean_from_response :delete, Repository.path(repo), options
      end
      alias :delete_repo :delete_repository

      # Transfer repository
      #
      # Transfer a repository owned by your organization
      #
      # @see https://developer.github.com/v3/repos/#transfer-a-repository
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param new_owner [String] The username or organization name the repository will be transferred to.
      # @param options [Array<Integer>] :team_ids ID of the team or teams to add to the repository. Teams can only be added to organization-owned repositories.
      # @return [Sawyer::Resource] Repository info for the transferred repository
      def transfer_repository(repo, new_owner, options = {})
        options = ensure_api_media_type(:transfer_repository, options)
        post "#{Repository.path repo}/transfer", options.merge({ new_owner: new_owner })
      end
      alias :transfer_repo :transfer_repository

      # Hide a public repository
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Sawyer::Resource] Updated repository info
      def set_private(repo, options = {})
        # GitHub Api for setting private updated to use private attr, rather than public
        update_repository repo, options.merge({ :private => true })
      end

      # Unhide a private repository
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Sawyer::Resource] Updated repository info
      def set_public(repo, options = {})
        # GitHub Api for setting private updated to use private attr, rather than public
        update_repository repo, options.merge({ :private => false })
      end

      # Get deploy keys on a repo
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @return [Array<Sawyer::Resource>] Array of hashes representing deploy keys.
      # @see https://developer.github.com/v3/repos/keys/#list-deploy-keys
      # @example
      #   @client.deploy_keys('octokit/octokit.rb')
      # @example
      #   @client.list_deploy_keys('octokit/octokit.rb')
      def deploy_keys(repo, options = {})
        paginate "#{Repository.path repo}/keys", options
      end
      alias :list_deploy_keys :deploy_keys

      # Get a single deploy key for a repo
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Deploy key ID.
      # @return [Sawyer::Resource] Deploy key.
      # @see https://developer.github.com/v3/repos/keys/#get-a-deploy-key
      # @example
      #   @client.deploy_key('octokit/octokit.rb', 8675309)
      def deploy_key(repo, id, options={})
        get "#{Repository.path repo}/keys/#{id}", options
      end

      # Add deploy key to a repo
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param title [String] Title reference for the deploy key.
      # @param key [String] Public key.
      # @return [Sawyer::Resource] Hash representing newly added key.
      # @see https://developer.github.com/v3/repos/keys/#add-a-new-deploy-key
      # @example
      #    @client.add_deploy_key('octokit/octokit.rb', 'Staging server', 'ssh-rsa AAA...')
      def add_deploy_key(repo, title, key, options = {})
        post "#{Repository.path repo}/keys", options.merge(:title => title, :key => key)
      end

      # Edit a deploy key
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Deploy key ID.
      # @param options [Hash] Attributes to edit.
      # @option title [String] Key title.
      # @option key [String] Public key.
      # @return [Sawyer::Resource] Updated deploy key.
      # @deprecated This method is no longer supported in the API
      # @see https://developer.github.com/changes/2014-02-24-finer-grained-scopes-for-ssh-keys/
      # @see https://developer.github.com/v3/repos/keys/#edit-a-deploy-key
      # @example Update the key for a deploy key.
      #   @client.edit_deploy_key('octokit/octokit.rb', 8675309, :key => 'ssh-rsa BBB...')
      # @example
      #   @client.update_deploy_key('octokit/octokit.rb', 8675309, :title => 'Uber', :key => 'ssh-rsa BBB...'))
      def edit_deploy_key(repo, id, options)
        patch "#{Repository.path repo}/keys/#{id}", options
      end
      alias :update_deploy_key :edit_deploy_key

      # Remove deploy key from a repo
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param id [Integer] Id of the deploy key to remove.
      # @return [Boolean] True if key removed, false otherwise.
      # @see https://developer.github.com/v3/repos/keys/#remove-a-deploy-key
      # @example
      #   @client.remove_deploy_key('octokit/octokit.rb', 100000)
      def remove_deploy_key(repo, id, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/keys/#{id}", options
      end

      # List collaborators
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @option options [String] :affiliation Filters the return array by affiliation.
      #   Can be one of: <tt>outside</tt> or <tt>all</tt>.
      #   If not specified, defaults to <tt>all</tt>
      # @return [Array<Sawyer::Resource>] Array of hashes representing collaborating users.
      # @see https://developer.github.com/v3/repos/collaborators/#list-collaborators
      # @example
      #   Octokit.collaborators('octokit/octokit.rb')
      # @example
      #   Octokit.collabs('octokit/octokit.rb')
      # @example
      #   @client.collabs('octokit/octokit.rb')
      def collaborators(repo, options = {})
        paginate "#{Repository.path repo}/collaborators", options
      end
      alias :collabs :collaborators

      # Add collaborator to repo
      #
      # This can also be used to update the permission of an existing collaborator
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param collaborator [String] Collaborator GitHub username to add.
      # @option options [String] :permission The permission to grant the collaborator.
      #   Only valid on organization-owned repositories.
      #   Can be one of: <tt>pull</tt>, <tt>push</tt>, or <tt>admin</tt>.
      #   If not specified, defaults to <tt>push</tt>
      # @return [Boolean] True if collaborator added, false otherwise.
      # @see https://developer.github.com/v3/repos/collaborators/#add-user-as-a-collaborator
      # @example
      #   @client.add_collaborator('octokit/octokit.rb', 'holman')
      # @example
      #   @client.add_collab('octokit/octokit.rb', 'holman')
      # @example Add a collaborator with admin permissions
      #   @client.add_collaborator('octokit/octokit.rb', 'holman', permission: 'admin')
      def add_collaborator(repo, collaborator, options = {})
        boolean_from_response :put, "#{Repository.path repo}/collaborators/#{collaborator}", options
      end
      alias :add_collab :add_collaborator

      # Remove collaborator from repo.
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param collaborator [String] Collaborator GitHub username to remove.
      # @return [Boolean] True if collaborator removed, false otherwise.
      # @see https://developer.github.com/v3/repos/collaborators/#remove-user-as-a-collaborator
      # @example
      #   @client.remove_collaborator('octokit/octokit.rb', 'holman')
      # @example
      #   @client.remove_collab('octokit/octokit.rb', 'holman')
      def remove_collaborator(repo, collaborator, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/collaborators/#{collaborator}", options
      end
      alias :remove_collab :remove_collaborator

      # Checks if a user is a collaborator for a repo.
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param collaborator [String] Collaborator GitHub username to check.
      # @return [Boolean] True if user is a collaborator, false otherwise.
      # @see https://developer.github.com/v3/repos/collaborators/#check-if-a-user-is-a-collaborator
      # @example
      #   @client.collaborator?('octokit/octokit.rb', 'holman')
      def collaborator?(repo, collaborator, options={})
        boolean_from_response :get, "#{Repository.path repo}/collaborators/#{collaborator}", options
      end

      # Get a user's permission level for a repo.
      #
      # Requires authenticated client
      #
      # @return [Sawyer::Resource] Hash representing the user's permission level for the given repository
      # @see https://developer.github.com/v3/repos/collaborators/#review-a-users-permission-level
      # @example
      #   @client.permission_level('octokit/octokit.rb', 'lizzhale')
      def permission_level(repo, collaborator, options={})
        get "#{Repository.path repo}/collaborators/#{collaborator}/permission", options
      end

      # List teams for a repo
      #
      # Requires authenticated client that is an owner or collaborator of the repo.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing teams.
      # @see https://developer.github.com/v3/repos/#list-teams
      # @example
      #   @client.repository_teams('octokit/pengwynn')
      # @example
      #   @client.repo_teams('octokit/pengwynn')
      # @example
      #   @client.teams('octokit/pengwynn')
      def repository_teams(repo, options = {})
        paginate "#{Repository.path repo}/teams", options
      end
      alias :repo_teams :repository_teams
      alias :teams :repository_teams

      # List all topics for a repository
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Sawyer::Resource] representing the topics for given repo
      # @see https://developer.github.com/v3/repos/#list-all-topics-for-a-repository
      # @example List topics for octokit/octokit.rb
      #   Octokit.topics('octokit/octokit.rb')
      # @example List topics for octokit/octokit.rb
      #   client.topics('octokit/octokit.rb')      
      def topics(repo, options = {})
        opts = ensure_api_media_type(:topics, options)
        paginate "#{Repository.path repo}/topics", opts
      end

      # Replace all topics for a repository
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Repository, Hash] A Github repository
      # @param names [Array] An array of topics to add to the repository.
      # @return [Sawyer::Resource] representing the replaced topics for given repo
      # @see https://developer.github.com/v3/repos/#replace-all-topics-for-a-repository
      # @example Replace topics for octokit/octokit.rb
      #   client.replace_all_topics('octokit/octokit.rb', ['octocat', 'atom', 'electron', 'API'])
      # @example Clear all topics for octokit/octokit.rb
      #   client.replace_all_topics('octokit/octokit.rb', [])
      def replace_all_topics(repo, names, options = {})
        opts = ensure_api_media_type(:topics, options)
        put "#{Repository.path repo}/topics", opts.merge(:names => names)
      end

      # List contributors to a repo
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param anon [Boolean] Set true to include anonymous contributors.
      # @return [Array<Sawyer::Resource>] Array of hashes representing users.
      # @see https://developer.github.com/v3/repos/#list-contributors
      # @example
      #   Octokit.contributors('octokit/octokit.rb', true)
      # @example
      #   Octokit.contribs('octokit/octokit.rb')
      # @example
      #   @client.contribs('octokit/octokit.rb')
      def contributors(repo, anon = nil, options = {})
        options[:anon] = 1 if anon.to_s[/1|true/]
        paginate "#{Repository.path repo}/contributors", options
      end
      alias :contribs :contributors

      # List stargazers of a repo
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing users.
      # @see https://developer.github.com/v3/activity/starring/#list-stargazers
      # @example
      #   Octokit.stargazers('octokit/octokit.rb')
      # @example
      #   @client.stargazers('octokit/octokit.rb')
      def stargazers(repo, options = {})
        paginate "#{Repository.path repo}/stargazers", options
      end

      # @deprecated Use {#stargazers} instead
      #
      # List watchers of repo.
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing users.
      # @see https://developer.github.com/v3/repos/watching/#list-watchers
      # @example
      #   Octokit.watchers('octokit/octokit.rb')
      # @example
      #   @client.watchers('octokit/octokit.rb')
      def watchers(repo, options = {})
        paginate "#{Repository.path repo}/watchers", options
      end

      # List forks
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing repos.
      # @see https://developer.github.com/v3/repos/forks/#list-forks
      # @example
      #   Octokit.forks('octokit/octokit.rb')
      # @example
      #   Octokit.network('octokit/octokit.rb')
      # @example
      #   @client.forks('octokit/octokit.rb')
      def forks(repo, options = {})
        paginate "#{Repository.path repo}/forks", options
      end
      alias :network :forks

      # List languages of code in the repo.
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of Hashes representing languages.
      # @see https://developer.github.com/v3/repos/#list-languages
      # @example
      #   Octokit.languages('octokit/octokit.rb')
      # @example
      #   @client.languages('octokit/octokit.rb')
      def languages(repo, options = {})
        paginate "#{Repository.path repo}/languages", options
      end

      # List tags
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing tags.
      # @see https://developer.github.com/v3/repos/#list-tags
      # @example
      #   Octokit.tags('octokit/octokit.rb')
      # @example
      #   @client.tags('octokit/octokit.rb')
      def tags(repo, options = {})
        paginate "#{Repository.path repo}/tags", options
      end

      # List branches
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing branches.
      # @see https://developer.github.com/v3/repos/#list-branches
      # @example
      #   Octokit.branches('octokit/octokit.rb')
      # @example
      #   @client.branches('octokit/octokit.rb')
      def branches(repo, options = {})
        paginate "#{Repository.path repo}/branches", options
      end

      # Get a single branch from a repository
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param branch [String] Branch name
      # @return [Sawyer::Resource] The branch requested, if it exists
      # @see https://developer.github.com/v3/repos/#get-branch
      # @example Get branch 'master` from octokit/octokit.rb
      #   Octokit.branch("octokit/octokit.rb", "master")
      def branch(repo, branch, options = {})
        get "#{Repository.path repo}/branches/#{branch}", options
      end
      alias :get_branch :branch

      # Lock a single branch from a repository
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param branch [String] Branch name
      # @option options [Hash] :required_status_checks If not null, the following keys are required:  
      #   <tt>:enforce_admins [boolean] Enforce required status checks for repository administrators.</tt>  
      #   <tt>:strict [boolean] Require branches to be up to date before merging.</tt>  
      #   <tt>:contexts [Array] The list of status checks to require in order to merge into this branch</tt>  
      #
      # @option options [Hash] :restrictions If not null, the following keys are required:
      #   <tt>:users [Array] The list of user logins with push access</tt>  
      #   <tt>:teams [Array] The list of team slugs with push access</tt>.  
      #
      #   Teams and users restrictions are only available for organization-owned repositories.
      # @return [Sawyer::Resource] The protected branch
      # @see https://developer.github.com/v3/repos/#enabling-and-disabling-branch-protection
      # @example
      #   @client.protect_branch('octokit/octokit.rb', 'master', foo)
      def protect_branch(repo, branch, options = {})
        opts = ensure_api_media_type(:branch_protection, options)
        opts[:restrictions] ||= nil
        opts[:required_status_checks] ||= nil
        put "#{Repository.path repo}/branches/#{branch}/protection", opts
      end

      # Get branch protection summary
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param branch [String] Branch name
      # @return [Sawyer::Resource, nil] Branch protection summary or nil if the branch
      #   is not protected
      # @see https://developer.github.com/v3/repos/branches/#get-branch-protection
      # @example
      #   @client.branch_protection('octokit/octokit.rb', 'master')
      def branch_protection(repo, branch, options = {})
        opts = ensure_api_media_type(:branch_protection, options)
        begin
          get "#{Repository.path repo}/branches/#{branch}/protection", opts
        rescue Octokit::BranchNotProtected
          nil
        end
      end

      # Unlock a single branch from a repository
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param branch [String] Branch name
      # @return [Sawyer::Resource] The unprotected branch
      # @see https://developer.github.com/v3/repos/#enabling-and-disabling-branch-protection
      # @example
      #   @client.unprotect_branch('octokit/octokit.rb', 'master')
      def unprotect_branch(repo, branch, options = {})
        opts = ensure_api_media_type(:branch_protection, options)
        boolean_from_response :delete, "#{Repository.path repo}/branches/#{branch}/protection", opts
      end

      # List users available for assigning to issues.
      #
      # Requires authenticated client for private repos.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of hashes representing users.
      # @see https://developer.github.com/v3/issues/assignees/#list-assignees
      # @example
      #   Octokit.repository_assignees('octokit/octokit.rb')
      # @example
      #   Octokit.repo_assignees('octokit/octokit.rb')
      # @example
      #   @client.repository_assignees('octokit/octokit.rb')
      def repository_assignees(repo, options = {})
        paginate "#{Repository.path repo}/assignees", options
      end
      alias :repo_assignees :repository_assignees

      # Check to see if a particular user is an assignee for a repository.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param assignee [String] User login to check
      # @return [Boolean] True if assignable on project, false otherwise.
      # @see https://developer.github.com/v3/issues/assignees/#check-assignee
      # @example
      #   Octokit.check_assignee('octokit/octokit.rb', 'andrew')
      def check_assignee(repo, assignee, options = {})
        boolean_from_response :get, "#{Repository.path repo}/assignees/#{assignee}", options
      end

      # List watchers subscribing to notifications for a repo
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Array<Sawyer::Resource>] Array of users watching.
      # @see https://developer.github.com/v3/activity/watching/#list-watchers
      # @example
      #   @client.subscribers("octokit/octokit.rb")
      def subscribers(repo, options = {})
        paginate "#{Repository.path repo}/subscribers", options
      end

      # Get a repository subscription
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Sawyer::Resource] Repository subscription.
      # @see https://developer.github.com/v3/activity/watching/#get-a-repository-subscription
      # @example
      #   @client.subscription("octokit/octokit.rb")
      def subscription(repo, options = {})
        get "#{Repository.path repo}/subscription", options
      end

      # Update repository subscription
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param options [Hash]
      #
      # @option options [Boolean] :subscribed Determines if notifications
      #   should be received from this repository.
      # @option options [Boolean] :ignored Deterimines if all notifications
      #   should be blocked from this repository.
      # @return [Sawyer::Resource] Updated repository subscription.
      # @see https://developer.github.com/v3/activity/watching/#set-a-repository-subscription
      # @example Subscribe to notifications for a repository
      #   @client.update_subscription("octokit/octokit.rb", {subscribed: true})
      def update_subscription(repo, options = {})
        put "#{Repository.path repo}/subscription", options
      end

      # Delete a repository subscription
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Boolean] True if subscription deleted, false otherwise.
      # @see https://developer.github.com/v3/activity/watching/#delete-a-repository-subscription
      #
      # @example
      #   @client.delete_subscription("octokit/octokit.rb")
      def delete_subscription(repo, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/subscription", options
      end
    end
  end
end
