module Octokit
  class Client

    # Methods for Projects API
    #
    # @see https://developer.github.com/v3/repos/projects
    module Projects

      # List projects for a repository
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] Repository projects
      # @see https://developer.github.com/v3/projects/#list-repository-projects 
      # @example
      #   @client.projects('octokit/octokit.rb')
      def projects(repo, options = {})
        opts = ensure_api_media_type(:projects, options)
        paginate "#{Repository.path repo}/projects", opts
      end

      # Create a project
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param name [String] Project name
      # @option options [String] :body Body of the project
      # @return [Sawyer::Resource] Fresh new project
      # @see https://developer.github.com/v3/projects/#create-a-repository-project 
      # @example Create project with only a name
      #   @client.create_project('octokit/octokit.rb', 'implement new APIs')
      #
      # @example Create project with name and body
      #   @client.create_project('octokit/octokit.rb', 'bugs be gone', body: 'Fix all the bugs @joeyw creates')
      def create_project(repo, name, options = {})
        opts = ensure_api_media_type(:projects, options)
        opts[:name] = name
        post "#{Repository.path repo}/projects", opts
      end

      # List organization projects
      #
      # Requires authenticated client
      #
      # @param org [String] A GitHub organization
      # @return [Array<Sawyer::Resource>] Organization projects
      # @see https://developer.github.com/v3/projects/#list-organization-projects
      # @example
      #   @client.org_projects("octokit")
      def org_projects(org, options = {})
        opts = ensure_api_media_type(:projects, options)
        get "orgs/#{org}/projects", opts
      end
      alias :organization_projects :org_projects

      # Create organization project
      #
      # Requires authenticated client
      #
      # @param org [String] A GitHub organization
      # @param name [String] Project name
      # @option options [String] :body Project body
      # @return [Sawyer::Resource] Organization project
      # @see https://developer.github.com/v3/projects/#create-an-organization-project
      # @example Create with only a name
      #   @client.create_org_project("octocat", "make more octocats")
      # @example Create a project with name and body
      #   @client.create_org_project("octokit", "octocan", body: 'Improve clients')
      def create_org_project(org, name, options = {})
        opts = ensure_api_media_type(:projects, options)
        opts[:name] = name
        post "orgs/#{org}/projects", opts
      end
      alias :create_organization_project :create_org_project

      # Get a project by id 
      #
      # @param id [Integer] Project id
      # @return [Sawyer::Resource] Project
      # @see https://developer.github.com/v3/projects/#get-a-project 
      # @example
      #   Octokit.project(123942)
      def project(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        get "projects/#{id}", opts
      end

      # Update a project
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project id
      # @option options [String] :name Project name
      # @option options [String] :body Project body
      # @return [Sawyer::Resource] Project
      # @see https://developer.github.com/v3/projects/#update-a-project 
      # @example Update project name
      #   @client.update_project(123942, name: 'New name')
      def update_project(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        patch "projects/#{id}", opts
      end

      # Delete a project
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project id
      # @return [Boolean] Result of deletion
      # @see https://developer.github.com/v3/projects/#delete-a-project 
      # @example
      #   @client.delete_project(123942)
      def delete_project(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        boolean_from_response :delete, "projects/#{id}", opts
      end

      # List project columns
      #
      # @param id [Integer] Project id 
      # @return [Array<Sawyer::Resource>] List of project columns
      # @see https://developer.github.com/v3/projects/columns/#list-project-columns 
      # @example
      #   @client.project_columns(123942)
      def project_columns(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        paginate "projects/#{id}/columns", opts
      end

      # Create a project column
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project column id
      # @param name [String] New column name
      # @return [Sawyer::Resource] Newly created column
      # @see https://developer.github.com/v3/projects/columns/#create-a-project-column 
      # @example
      #   @client.create_project_column(123942, "To Dones")
      def create_project_column(id, name, options = {})
        opts = ensure_api_media_type(:projects, options)
        opts[:name] = name
        post "projects/#{id}/columns", opts
      end

      # Get a project column by ID
      #
      # @param id [Integer] Project column id
      # @return [Sawyer::Resource] Project column
      # @see https://developer.github.com/v3/projects/columns/#get-a-project-column 
      # @example
      #   Octokit.project_column(30294)
      def project_column(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        get "projects/columns/#{id}", opts
      end

      # Update a project column
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project column id
      # @param name [String] New column name
      # @return [Sawyer::Resource] Updated column
      # @see https://developer.github.com/v3/projects/columns/#update-a-project-column 
      # @example
      #   @client.update_project_column(30294, "new column name")
      def update_project_column(id, name, options = {})
        opts = ensure_api_media_type(:projects, options)
        opts[:name] = name
        patch "projects/columns/#{id}", opts
      end

      # Delete a project column
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project column id
      # @return [Boolean] Result of deletion request, true when deleted
      # @see https://developer.github.com/v3/projects/columns/#delete-a-project-column 
      # @example
      #   @client.delete_project_column(30294)
      def delete_project_column(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        boolean_from_response :delete, "projects/columns/#{id}", opts
      end

      # Move a project column
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project column id
      # @param position [String] New position for the column. Can be one of 
      #   <tt>first</tt>, <tt>last</tt>, or <tt>after:<column-id></tt>, where
      #   <tt><column-id></tt> is the id value of a column in the same project.
      # @return [Sawyer::Resource] Result
      # @see https://developer.github.com/v3/projects/columns/#move-a-project-column
      # @example
      #   @client.move_project_column(30294, "last")
      def move_project_column(id, position, options = {})
        opts = ensure_api_media_type(:projects, options)
        opts[:position] = position
        post "projects/columns/#{id}/moves", opts
      end

      # List columns cards
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project column id
      # @return [Array<Sawyer::Resource>] Cards in the column
      # @see https://developer.github.com/v3/projects/cards/#list-project-cards
      # @example
      #   @client.column_cards(30294)
      def column_cards(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        paginate "projects/columns/#{id}/cards", opts
      end

      # Create project card
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project column id
      # @option options [String] :note Card contents for a note type
      # @option options [Integer] :content_id Issue ID for the card contents
      # @option options [String] :content_type Type of content to associate
      #   with the card. <tt>Issue</tt> is presently the only avaiable value
      # @note If :note is supplied, :content_id and :content_type must be
      #   excluded. Similarly, if :content_id is supplied, :content_type must
      #   be set and :note must not be included.
      # @return [Sawyer::Resource] Newly created card
      # @see https://developer.github.com/v3/projects/cards/#create-a-project-card
      # @example Create a project card with a note
      #   @client.create_project_card(123495, note: 'New note card')
      # @example Create a project card for an repository issue
      #   @client.create_project_card(123495, content_id: 1, content_type: 'Issue')
      def create_project_card(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        post "projects/columns/#{id}/cards", opts
      end

      # Get a project card
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project card id
      # @return [Sawyer::Resource] Project card
      # @see https://developer.github.com/v3/projects/cards/#get-a-project-card
      # @example
      #   @client.project_card(123495)
      def project_card(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        get "projects/columns/cards/#{id}", opts
      end

      # Update a project card
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project card id
      # @option options [String] :note The card's note content. Only valid for
      #   cards without another type of content, so this cannot be specified if
      #   the card already has a content_id and content_type.
      # @return [Sawyer::Resource] Updated project card
      # @see https://developer.github.com/v3/projects/cards/#update-a-project-card
      # @example
      #   @client.update_project_card(12345, note: 'new note')
      def update_project_card(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        patch "projects/columns/cards/#{id}", opts
      end

      # Move a project card
      #
      # Requires authenticated client
      #
      # @param id [Integer] Project card id
      # @param position [String] Can be one of <tt>top</tt>, <tt>bottom</tt>,
      #   or <tt>after:<card-id></tt>, where <card-id> is the id value of a
      #   card in the same column, or in the new column specified by column_id.
      # @option options [Integer] :column_id The column id to move the card to,
      #   must be column in same project
      # @return [Sawyer::Resource] Empty sawyer resource
      # @see https://developer.github.com/v3/projects/cards/#move-a-project-card
      # @example Move a card to the bottom of the same column
      #   @client.move_project_card(123495, 'bottom')
      # @example Move a card to the top of another column
      #   @client.move_project_card(123495, 'top', column_id: 59402)
      def move_project_card(id, position, options = {})
        opts = ensure_api_media_type(:projects, options)
        opts[:position] = position
        post "projects/columns/cards/#{id}/moves", opts
      end

      # Delete a project card
      # 
      # Requires authenticated client
      #
      # @param id [Integer] Project card id
      # @return [Boolean] True of deleted, false otherwise
      # @see https://developer.github.com/v3/projects/cards/#delete-a-project-card
      # @example
      #   @client.delete_project_card(123495)
      def delete_project_card(id, options = {})
        opts = ensure_api_media_type(:projects, options)
        boolean_from_response :delete, "projects/columns/cards/#{id}", opts
      end

    end # Projects
  end
end
