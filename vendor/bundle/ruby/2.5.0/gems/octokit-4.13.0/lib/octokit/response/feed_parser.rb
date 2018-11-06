require 'faraday'

module Octokit

  module Response

    # Parses RSS and Atom feed responses.
    class FeedParser < Faraday::Response::Middleware

      private

      def on_complete(env)
        if env[:response_headers]["content-type"] =~ /(\batom|\brss)/
          require 'rss'
          env[:body] = RSS::Parser.parse env[:body]
        end
      end

    end
  end
end
