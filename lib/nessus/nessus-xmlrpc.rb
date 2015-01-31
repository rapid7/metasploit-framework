require 'net/http'

module Nessus

   class Client
      class << self
        @uri
        @connection
        @token
      end
      
      def initialize(host, username = nil, password = nil, ssl_option = nil)
         @uri = URI.parse('https://127.0.0.1:8834')
         @connection = Net::HTTP.new(@uri.host, @uri.port)
         @connection.use_ssl = true
         @connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
         yield @connection if block_given?

         authenticate(username, password) if username && password
      end

      def authenticate(username, password)

         payload = {
            :username => username,
            :password => password,
            :json => 1,
         }
         request = Net::HTTP::Post.new("/session")
         request.set_form_data(payload)
         resp = @connection.request(request)
         resp = JSON.parse(resp.body)
         @token = "token=#{resp['token']}"
         true
      end
      alias_method :login, :authenticate
      
      def authenticated
         if (@token && @token.include?('token='))
            return true
         else
            return false
         end
      end

      def get_server_properties
         resp = connection.get "/server/properties"
         resp = JSON.parse(resp.body)
         return resp
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
         request = Net::HTTP::Get.new("/folders")
         request.add_field("X-Cookie",@token)
         resp = @connection.request(request)
         resp = JSON.parse(resp.body)
         return resp
      end

      def list_scanners
         request = Net::HTTP::Get.new("/scanners")
         request.add_field("X-Cookie",@token)
         resp = @connection.request(request)
         resp = JSON.parse(resp.body)
         return resp
      end

      def list_families
         request = Net::HTTP::Get.new("/plugins/families")
         request.add_field("X-Cookie",@token)
         resp = @connection.request(request)
         resp = JSON.parse(resp.body)
         return resp
      end

      def list_plugins(family_id)
         request = Net::HTTP::Get.new("/plugins/families/#{family_id}")
         request.add_field("X-Cookie",@token)
         resp = @connection.request(request)
         resp = JSON.parse(resp.body)
         return resp
      end

      def plugin_details(plugin_id)
         request = Net::HTTP::Get.new("/plugins/plugin/#{plugin_id}")
         request.add_field("X-Cookie",@token)
         resp = @connection.request(request)
         resp = JSON.parse(resp.body)
         return resp
      end
    
      def is_admin
         request = Net::HTTP::Get.new("/session")
         request.add_field("X-Cookie",@token)
         resp = @connection.request(request)
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

      def scan_launch(scan_id)
         resp = connection.post "/scans/#{scan_id}/launch"
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
