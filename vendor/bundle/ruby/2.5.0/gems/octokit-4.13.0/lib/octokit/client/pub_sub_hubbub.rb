module Octokit
  class Client

    # Methods for the PubSubHubbub API
    #
    # @see https://developer.github.com/v3/repos/hooks/#pubsubhubbub
    module PubSubHubbub

      # Subscribe to a pubsub topic
      #
      # @param topic [String] A recoginized and supported pubsub topic
      # @param callback [String] A callback url to be posted to when the topic event is fired
      # @param secret [String] An optional shared secret used to generate a SHA1 HMAC of the outgoing body content
      # @return [Boolean] true if the subscribe was successful, otherwise an error is raised
      # @see https://developer.github.com/v3/repos/hooks/#subscribing
      # @example Subscribe to push events from one of your repositories, having an email sent when fired
      #   client = Octokit::Client.new(:oauth_token = "token")
      #   client.subscribe("https://github.com/joshk/devise_imapable/events/push", "github://Email?address=josh.kalderimis@gmail.com")
      def subscribe(topic, callback, secret = nil)
        options = {
          :"hub.callback" => callback,
          :"hub.mode" => "subscribe",
          :"hub.topic" => topic
        }
        options.merge!(:"hub.secret" => secret) unless secret.nil?

        response = pub_sub_hubbub_request(options)

        response.status == 204
      end

      # Unsubscribe from a pubsub topic
      #
      # @param topic [String] A recoginized pubsub topic
      # @param callback [String] A callback url to be unsubscribed from
      # @return [Boolean] true if the unsubscribe was successful, otherwise an error is raised
      # @see https://developer.github.com/v3/repos/hooks/#subscribing
      # @example Unsubscribe to push events from one of your repositories, no longer having an email sent when fired
      #   client = Octokit::Client.new(:oauth_token = "token")
      #   client.unsubscribe("https://github.com/joshk/devise_imapable/events/push", "github://Email?address=josh.kalderimis@gmail.com")
      def unsubscribe(topic, callback)
        options = {
          :"hub.callback" => callback,
          :"hub.mode" => "unsubscribe",
          :"hub.topic" => topic
        }
        response = pub_sub_hubbub_request(options)

        response.status == 204
      end

      # Subscribe to a repository through pubsub
      #
      # @param repo [String, Repository, Hash] A GitHub repository
      # @param service_name [String] service name owner
      # @param service_arguments [Hash] params that will be passed by subscribed hook.
      #    List of services is available @ https://github.com/github/github-services/tree/master/docs.
      #    Please refer Data node for complete list of arguments.
      # @param secret [String] An optional shared secret used to generate a SHA1 HMAC of the outgoing body content
      # @return [Boolean] True if subscription successful, false otherwise
      # @see https://developer.github.com/v3/repos/hooks/#subscribing
      # @example Subscribe to push events to one of your repositories to Travis-CI
      #    client = Octokit::Client.new(:oauth_token = "token")
      #    client.subscribe_service_hook('joshk/device_imapable', 'Travis', { :token => "test", :domain => "domain", :user => "user" })
      def subscribe_service_hook(repo, service_name, service_arguments = {}, secret = nil)
        topic = "#{Octokit.web_endpoint}#{Repository.new(repo)}/events/push"
        callback = "github://#{service_name}?#{service_arguments.collect{ |k,v| [ k,v ].map{ |p| URI.encode_www_form_component(p) }.join("=") }.join("&") }"
        subscribe(topic, callback, secret)
      end

      # Unsubscribe repository through pubsub
      #
      # @param repo [String, Repository, Hash] A GitHub repository
      # @param service_name [String] service name owner
      #    List of services is available @ https://github.com/github/github-services/tree/master/docs.
      # @see https://developer.github.com/v3/repos/hooks/#subscribing
      # @example Subscribe to push events to one of your repositories to Travis-CI
      #    client = Octokit::Client.new(:oauth_token = "token")
      #    client.unsubscribe_service_hook('joshk/device_imapable', 'Travis')
      def unsubscribe_service_hook(repo, service_name)
        topic = "#{Octokit.web_endpoint}#{Repository.new(repo)}/events/push"
        callback = "github://#{service_name}"
        unsubscribe(topic, callback)
      end

      private

      def pub_sub_hubbub_request(options = {})
        # This method is janky, bypass normal stack so we don't
        # serialize request as JSON
        conn = Faraday.new(:url => @api_endpoint) do |http|
          http.headers[:user_agent] = user_agent
          if basic_authenticated?
            http.basic_auth(@login, @password)
          elsif token_authenticated?
            http.authorization 'token', @access_token
          end
          http.request  :url_encoded
          http.use Octokit::Response::RaiseError
          http.adapter  Faraday.default_adapter
        end

        conn.post do |req|
          req.url "hub"
          req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
          req.body = options
        end
      end
    end
  end
end
