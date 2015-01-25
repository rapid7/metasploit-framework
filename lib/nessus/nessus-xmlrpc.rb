require 'faraday'
require 'cgi'
require 'json'

module Nessus

   class Client
      class << self
         # @!attribute verify_ssl
         #   @return [Boolean] whether to verify SSL with Faraday (default: true)
         attr_accessor :verify_ssl
      end
      
      def initialize(host, username = nil, password = nil, ssl_option = nil)
         connection_options = {}
         connection_options[:ssl] ||= {}
         if ssl_option == "ssl_verify"
            connection_options[:ssl][:verify] = true
         else
            connection_options[:ssl][:verify] = false
         end
         @connection = Faraday.new(host, connection_options)
         # @connection.headers[:user_agent] = "Nessus.rb v1.1".freeze

         # Allow passing a block to Faraday::Connection
         yield @connection if block_given?

         authenticate(username, password) if username && password
      end

      def authenticate(username, password)

         payload = {
            :username => username,
            :password => password,
            :json => 1,
         }
         resp = connection.post "/session", payload
         resp = JSON.parse(resp.body)
         if resp.include? "token"
            connection.headers["X-Cookie"] = "token=#{resp['token']}"
         end

         true
      end
      alias_method :login, :authenticate
      
      def authenticated
         headers = connection.headers
         if (headers["X-Cookie"] && headers["X-Cookie"].include?('token='))
            return true
         else
            return false
         end
      end

      def get_server_properties
         resp = connection.get "/server/properties"
         resp = JSON.parse(resp.body)
         puts resp.to_s
      end
   
      def user_add(username,password,permissions,type)
        payload = {
           :username => username,
           :password => password,
           :permissions => permissions,
           :type => type,
           :json => 1,
        }
        resp = connection.post "/users", payload
        resp = JSON.parse(resp.body)
        return resp
      end

      def user_delete(user_id)
         resp = connection.delete "/users/#{user_id}"
         return resp.status
      end

      def user_chpasswd(user_id, password)
         payload = {
            :password => password,
            :json => 1,
         }
         resp = connection.put "/users/#{user_id}/chpasswd", payload
         return resp.status
      end

      def user_logout
         resp = connection.delete "/session"
         return resp.status
      end

      def list_policies
         resp = connection.get "/policies"
         resp = JSON.parse(resp.body)["policies"]
         return resp
      end

      def list_users
         resp = connection.get "/users"
         resp = JSON.parse(resp.body)["users"]
         return resp
      end

      def list_folders
         resp = connection.get '/folders'
         resp = JSON.parse(resp.body)["folders"]
         return resp
      end

      def list_scanners
         resp = connection.get "/scanners"
         resp = JSON.parse(resp.body)
         return resp
      end
    
      def is_admin
         resp = connection.get "/session"
         resp = JSON.parse(resp.body)
         if resp["permissions"] == 128
            return true
         else
            return false
         end
      end

      def server_properties
         resp = connection.get "/server/properties"
         resp = JSON.parse(resp.body)
         return resp
      end

      def scan_create(uuid, name, description, targets)
         payload = {
            :uuid => uuid,
            :settings => {
               :name => name,
               :description => description,
               :text_targets => targets
               },
            }
         connection.headers["Content-Type"] = "application/json"
         resp = connection.post "/scans", payload.to_json
         resp = JSON.parse(resp.body)
         return resp
      end

      def server_status
         resp = connection.get "/server/status"
         resp = JSON.parse(resp.body)
         return resp
      end

      def scan_list
         resp = connection.get "/scans"
         resp = JSON.parse(resp.body)["scans"]
         return resp
      end

      def scan_pause(scan_id)
         resp = connection.post "/scans/#{scan_id}/pause"
         resp = JSON.parse(resp.body)
         return resp
      end

      def scan_resume(scan_id)
         resp = connection.post "/scans/#{scan_id}/resume"
         resp = JSON.parse(resp.body)
         return resp
      end

      def scan_stop(scan_id)
         resp = connection.post "/scans/#{scan_id}/stop"
         resp = JSON.parse(resp.body)
         return resp
      end

      def policy_delete(policy_id)
         resp = connection.delete "/policies/#{policy_id}"
         return resp.status
      end
   end
end
