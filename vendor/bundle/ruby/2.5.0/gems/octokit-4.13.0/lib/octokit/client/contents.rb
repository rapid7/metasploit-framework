require 'base64'

module Octokit
  class Client

    # Methods for the Repo Contents API
    #
    # @see https://developer.github.com/v3/repos/contents/
    module Contents

      # Receive the default Readme for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @option options [String] :ref name of the Commit/Branch/Tag. Defaults to “master”.
      # @return [Sawyer::Resource] The detail of the readme
      # @see https://developer.github.com/v3/repos/contents/#get-the-readme
      # @example Get the readme file for a repo
      #   Octokit.readme("octokit/octokit.rb")
      def readme(repo, options={})
        get "#{Repository.path repo}/readme", options
      end

      # Receive a listing of a repository folder or the contents of a file
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @option options [String] :path A folder or file path
      # @option options [String] :ref name of the Commit/Branch/Tag. Defaults to “master”.
      # @return [Sawyer::Resource] The contents of a file or list of the files in the folder
      # @see https://developer.github.com/v3/repos/contents/#get-contents
      # @example List the contents of lib/octokit.rb
      #   Octokit.contents("octokit/octokit.rb", :path => 'lib/octokit.rb')
      def contents(repo, options={})
        options = options.dup
        repo_path = options.delete :path
        url = "#{Repository.path repo}/contents/#{repo_path}"
        get url, options
      end
      alias :content :contents

      # Add content to a repository
      #
      # @overload create_contents(repo, path, message, content = nil, options = {})
      #   @param repo [Integer, String, Repository, Hash] A GitHub repository
      #   @param path [String] A path for the new content
      #   @param message [String] A commit message for adding the content
      #   @param optional content [String] The content for the file
      #   @option options [String] :branch The branch on which to add the content
      #   @option options [String] :file Path or Ruby File object for content
      # @return [Sawyer::Resource] The contents and commit info for the addition
      # @see https://developer.github.com/v3/repos/contents/#create-a-file
      # @example Add content at lib/octokit.rb
      #   Octokit.create_contents("octokit/octokit.rb",
      #                    "lib/octokit.rb",
      #                    "Adding content",
      #                    "File content",
      #                    :branch => "my-new-feature")
      def create_contents(*args)
        args    = args.map { |item| item && item.dup }
        options = args.last.is_a?(Hash) ? args.pop : {}
        repo    = args.shift
        path    = args.shift
        message = args.shift
        content = args.shift
        if content.nil? && file = options.delete(:file)
          case file
          when String
            if File.exist?(file)
              file = File.open(file, "r")
              content = file.read
              file.close
            end
          when File, Tempfile
            content = file.read
            file.close
          end
        end
        raise ArgumentError.new("content or :file option required") if content.nil?
        options[:content] = Base64.respond_to?(:strict_encode64) ?
          Base64.strict_encode64(content) :
          Base64.encode64(content).delete("\n") # Ruby 1.9.2
        options[:message] = message
        url = "#{Repository.path repo}/contents/#{path}"
        put url, options
      end
      alias :create_content :create_contents
      alias :add_content :create_contents
      alias :add_contents :create_contents

      # Update content in a repository
      #
      # @overload update_contents(repo, path, message, sha, content = nil, options = {})
      #   @param repo [Integer, String, Repository, Hash] A GitHub repository
      #   @param path [String] A path for the content to update
      #   @param message [String] A commit message for updating the content
      #   @param sha [String] The _blob sha_ of the content to update
      #   @param content [String] The content for the file
      #   @option options [String] :branch The branch on which to update the content
      #   @option options [String] :file Path or Ruby File object for content
      # @return [Sawyer::Resource] The contents and commit info for the update
      # @see https://developer.github.com/v3/repos/contents/#update-a-file
      # @example Update content at lib/octokit.rb
      #   Octokit.update_contents("octokit/octokit.rb",
      #                    "lib/octokit.rb",
      #                    "Updating content",
      #                    "7eb95f97e1a0636015df3837478d3f15184a5f49",
      #                    "File content",
      #                    :branch => "my-new-feature")
      def update_contents(*args)
        options = args.last.is_a?(Hash) ? args.pop : {}
        repo    = args.shift
        path    = args.shift
        message = args.shift
        sha     = args.shift
        content = args.shift
        options.merge!(:sha => sha)
        create_contents(repo, path, message, content, options)
      end
      alias :update_content :update_contents

      # Delete content in a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param path [String] A path for the content to delete
      # @param message [String] A commit message for deleting the content
      # @param sha [String] The _blob sha_ of the content to delete
      # @option options [String] :branch The branch on which to delete the content
      # @return [Sawyer::Resource] The commit info for the delete
      # @see https://developer.github.com/v3/repos/contents/#delete-a-file
      # @example Delete content at lib/octokit.rb
      #   Octokit.delete_contents("octokit/octokit.rb",
      #                    "lib/octokit.rb",
      #                    "Deleting content",
      #                    "7eb95f97e1a0636015df3837478d3f15184a5f49",
      #                    :branch => "my-new-feature")
      def delete_contents(repo, path, message, sha, options = {})
        options[:message] = message
        options[:sha] = sha
        url = "#{Repository.path repo}/contents/#{path}"
        delete url, options
      end
      alias :delete_content :delete_contents
      alias :remove_content :delete_contents
      alias :remove_contents :delete_contents

      # This method will provide a URL to download a tarball or zipball archive for a repository.
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository.
      # @option options format [String] Either tarball (default) or zipball.
      # @option options [String] :ref Optional valid Git reference, defaults to master.
      # @return [String] Location of the download
      # @see https://developer.github.com/v3/repos/contents/#get-archive-link
      # @example Get archive link for octokit/octokit.rb
      #   Octokit.archive_link("octokit/octokit.rb")
      def archive_link(repo, options={})
        repo_ref = options.delete :ref
        format = (options.delete :format) || 'tarball'
        url = "#{Repository.path repo}/#{format}/#{repo_ref}"

        response = client_without_redirects.head(url, options)
        response.headers['Location']
      end
    end
  end
end
