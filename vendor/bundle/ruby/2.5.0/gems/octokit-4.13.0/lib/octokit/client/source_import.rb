module Octokit
  class Client

    # Methods for the Source Import API
    #
    # @see https://developer.github.com/v3/migration/source_imports
    module SourceImport

      # Start a source import to a GitHub repository using GitHub Importer.
      #
      # @overload start_source_import(repo, vcs, vcs_url, options = {})
      #   @deprecated
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository.
      #   @param vcs [String] The originating VCS type. Can be one of "subversion", "git", "mercurial", or "tfvc".
      #   @param vcs_url [String] The URL of the originating repository.
      #   @param options [Hash]
      #   @option options [String] :vcs_username If authentication is required, the username to provide to vcs_url.
      #   @option options [String] :vcs_password If authentication is required, the password to provide to vcs_url.
      #   @option options [String] :tfvc_project For a tfvc import, the name of the project that is being imported.
      # @overload start_source_import(repo, vcs_url, options = {})
      #   @param repo [Integer, String, Hash, Repository] A GitHub repository.
      #   @param vcs_url [String] The URL of the originating repository.
      #   @param options [Hash]
      #   @param options [String] :vcs The originating VCS type. Can be one of "subversion", "git", "mercurial", or "tfvc".
      #   @option options [String] :vcs_username If authentication is required, the username to provide to vcs_url.
      #   @option options [String] :vcs_password If authentication is required, the password to provide to vcs_url.
      #   @option options [String] :tfvc_project For a tfvc import, the name of the project that is being imported.
      # @return [Sawyer::Resource] Hash representing the repository import
      # @see https://developer.github.com/v3/migration/source_imports/#start-an-import
      #
      # @example
      #   @client.start_source_import("octokit/octokit.rb", "http://svn.mycompany.com/svn/myproject", {
      #    :vcs           => "subversion",
      #    :vcs_username" => "octocat",
      #    :vcs_password  => "secret"
      #   })
      def start_source_import(*args)
        arguments = Octokit::RepoArguments.new(args)
        vcs_url = arguments.pop
        vcs = arguments.pop
        if vcs
          octokit_warn "Octokit#start_source_import vcs parameter is now an option, please update your call before the next major Octokit version update."
          arguments.options.merge!(:vcs => vcs)
        end
        options = ensure_api_media_type(:source_imports, arguments.options.merge(:vcs_url => vcs_url))
        put "#{Repository.path arguments.repo}/import", options
      end

      # View the progress of an import.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Sawyer::Resource] Hash representing the progress of the import
      # @see https://developer.github.com/v3/migration/source_imports/#get-import-progress
      #
      # @example
      #   @client.source_import_progress("octokit/octokit.rb")
      def source_import_progress(repo, options = {})
        options = ensure_api_media_type(:source_imports, options)
        get "#{Repository.path repo}/import", options
      end

      # Update source import with authentication or project choice
      # Restart source import if no options are passed
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Sawyer::Resource] Hash representing the repository import
      # @see https://developer.github.com/v3/migration/source_imports/#update-existing-import
      # @option options [String] :vcs_username If authentication is required, the username to provide to vcs_url.
      # @option options [String] :vcs_password If authentication is required, the password to provide to vcs_url.
      # @option options [String] To update project choice, please refer to the project_choice array from the progress return hash for the exact attributes.
      # https://developer.github.com/v3/migration/source_imports/#update-existing-import
      #
      # @example
      #   @client.update_source_import("octokit/octokit.rb", {
      #    :vcs_username" => "octocat",
      #    :vcs_password  => "secret"
      #   })
      def update_source_import(repo, options = {})
        options = ensure_api_media_type(:source_imports, options)
        patch "#{Repository.path repo}/import", options
      end

      # List source import commit authors
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param options [Hash]
      # @option options [String] :since Only authors found after this id are returned.
      # @return [Array<Sawyer::Resource>] Array of hashes representing commit_authors.
      # @see https://developer.github.com/v3/migration/source_imports/#get-commit-authors
      #
      # @example
      #   @client.source_import_commit_authors("octokit/octokit.rb")
      def source_import_commit_authors(repo, options = {})
        options = ensure_api_media_type(:source_imports, options)
        get "#{Repository.path repo}/import/authors", options
      end

      # Update an author's identity for the import.
      #
      # @param author_url [String] The source import API url for the commit author
      # @param values [Hash] The updated author attributes
      # @option values [String] :email The new Git author email.
      # @option values [String] :name The new Git author name.
      # @return [Sawyer::Resource] Hash representing the updated commit author
      # @see https://developer.github.com/v3/migration/source_imports/#map-a-commit-author
      #
      # @example
      #   author_url = "https://api.github.com/repos/octokit/octokit.rb/import/authors/1"
      #   @client.map_source_import_commit_author(author_url, {
      #     :email => "hubot@github.com",
      #     :name => "Hubot the Robot"
      #   })
      def map_source_import_commit_author(author_url, values, options = {})
        options = ensure_api_media_type(:source_imports, options.merge(values))
        patch author_url, options
      end

      # Stop an import for a repository.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @return [Boolean] True if the import has been cancelled, false otherwise.
      # @see https://developer.github.com/v3/migration/source_imports/#cancel-an-import
      #
      # @example
      #   @client.cancel_source_import("octokit/octokit.rb")
      def cancel_source_import(repo, options = {})
        options = ensure_api_media_type(:source_imports, options)
        boolean_from_response :delete, "#{Repository.path repo}/import", options
      end

      # List source import large files
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param options [Hash]
      # @option options [Integer] :page Page of paginated results
      # @return [Array<Sawyer::Resource>] Array of hashes representing files over 100MB.
      # @see https://developer.github.com/v3/migration/source_imports/#get-large-files
      #
      # @example
      #   @client.source_import_large_files("octokit/octokit.rb")
      def source_import_large_files(repo, options = {})
        options = ensure_api_media_type(:source_imports, options)
        get "#{Repository.path repo}/import/large_files", options
      end

      # Set preference for using Git LFS to import files over 100MB
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param use_lfs [String] Preference for using Git LFS to import large files. Can be one of "opt_in" or "opt_out"
      # @return [Sawyer::Resource] Hash representing the repository import
      # @see https://developer.github.com/v3/migration/source_imports/#set-git-lfs-preference
      #
      # @example
      #   @client.opt_in_source_import_lfs("octokit/octokit.rb", "opt_in")
      def set_source_import_lfs_preference(repo, use_lfs, options = {})
        options = ensure_api_media_type(:source_imports, options.merge(:use_lfs => use_lfs))
        patch "#{Repository.path repo}/import/lfs", options
      end
    end
  end
end
