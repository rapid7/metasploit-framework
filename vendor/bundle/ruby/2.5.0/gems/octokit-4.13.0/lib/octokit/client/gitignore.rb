module Octokit
  class Client

    # Methods for the Gitignore API
    #
    # @see https://developer.github.com/v3/gitignore/
    module Gitignore

      # Listing available gitignore templates.
      #
      # These templates can be passed option when creating a repository.
      #
      # @see https://developer.github.com/v3/gitignore/#listing-available-templates
      #
      # @return [Array<String>] List of templates.
      #
      # @example Git all the gitignore templates
      #   @client.gitignore_templates
      def gitignore_templates(options = {})
        get "gitignore/templates", options
      end

      # Get a gitignore template.
      #
      # Use the raw {http://developer.github.com/v3/media/ media type} to get
      # the raw contents.
      #
      # @param template_name [String] Name of the template. Template names are
      #   case sensitive, make sure to use a valid name from the
      #   .gitignore_templates list.
      #
      # @see https://developer.github.com/v3/gitignore/#get-a-single-template
      #
      # @return [Sawyer::Resource] Gitignore template
      #
      # @example Get the Ruby gitignore template
      #   @client.gitignore_template('Ruby')
      def gitignore_template(template_name, options = {})
        get "gitignore/templates/#{template_name}", options
      end
    end
  end
end
