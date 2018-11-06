module Octokit
  class Client

    # Methods for licenses API
    #
    module Licenses

      # List all licenses
      #
      # @see https://developer.github.com/v3/licenses/#list-all-licenses
      # @return [Array<Sawyer::Resource>] A list of licenses
      # @example
      #   Octokit.licenses
      def licenses(options = {})
        options = ensure_api_media_type(:licenses, options)
        paginate "licenses", options
      end

      # List an individual license
      #
      # @see https://developer.github.com/v3/licenses/#get-an-individual-license
      # @param license_name [String] The license name
      # @return <Sawyer::Resource> An individual license
      # @example
      #   Octokit.license 'mit'
      def license(license_name, options = {})
        options = ensure_api_media_type(:licenses, options)
        get "licenses/#{license_name}", options
      end

      # Returns the contents of the repository’s license file, if one is detected.
      #
      # @see https://developer.github.com/v3/licenses/#get-the-contents-of-a-repositorys-license
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @option options [String] :ref name of the Commit/Branch/Tag. Defaults to 'master'.
      # @return [Sawyer::Resource] The detail of the license file
      # @example
      #   Octokit.repository_license_contents 'benbalter/licensee'
      def repository_license_contents(repo, options = {})
        options = ensure_api_media_type(:licenses, options)
        get "#{Repository.path repo}/license", options
      end
    end
  end
end
