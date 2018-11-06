module Octokit
  class Client

    # Methods for the Markdown API
    #
    # @see https://developer.github.com/v3/markdown/
    module Markdown

      # Render an arbitrary Markdown document
      #
      # @param text [String] Markdown source
      # @option options [String] (optional) :mode (`markdown` or `gfm`)
      # @option options [String] (optional) :context Repo context
      # @return [String] HTML renderization
      # @see https://developer.github.com/v3/markdown/#render-an-arbitrary-markdown-document
      # @example Render some GFM
      #   Octokit.markdown('Fixed in #111', :mode => "gfm", :context => "octokit/octokit.rb")
      def markdown(text, options = {})
        options[:text] = text
        options[:repo] = Repository.new(options[:repo]) if options[:repo]
        options[:accept] = 'application/vnd.github.raw'

        post "markdown", options
      end
    end
  end
end
