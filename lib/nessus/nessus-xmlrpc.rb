require 'net/http'

module Nessus

  class Client
    class << self
      @connection
      @token
    end
     
    def initialize(host, username = nil, password = nil, ssl_option = nil)
      uri = URI.parse(host)
      @connection = Net::HTTP.new(uri.host, uri.port)
      @connection.use_ssl = true
      if ssl_option == "ssl_verify"
      @connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
      else
        @connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
        
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
      request = Net::HTTP::Post.new("/users")
      request.set_form_data(payload)
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end
      
    def user_delete(user_id)
      request = Net::HTTP::Delete.new("/users/#{user_id}")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      return resp.code
    end
      
    def user_chpasswd(user_id, password)
      payload = {
        :password => password,
        :json => 1,
      }
      request = Net::HTTP::Put.new("/users/#{user_id}/chpasswd")
      request.set_form_data(payload)
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      return resp.code
    end
      
    def user_logout
      request = Net::HTTP::Delete.new("/session")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      return resp.code
    end

    def list_policies
      request = Net::HTTP::Get.new("/policies")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def list_users
      request = Net::HTTP::Get.new("/users")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
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
      request = Net::HTTP::Get.new("/server/properties")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
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
        :json => 1
      }
      request = Net::HTTP::Post.new("/scans")
      request.body = payload.to_json
      request.add_field("X-Cookie",@token)
      request["Content-Type"] = "application/json"
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def scan_launch(scan_id)
      request = Net::HTTP::Post.new("/scans/#{scan_id}/launch")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def server_status
      request = Net::HTTP::Get.new("/server/status")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def scan_list
      request = Net::HTTP::Get.new("/scans")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def scan_pause(scan_id)
      request = Net::HTTP::Post.new("/scans/#{scan_id}/pause")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def scan_resume(scan_id)
      request = Net::HTTP::Post.new("/scans/#{scan_id}/resume")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def scan_stop(scan_id)
      request = Net::HTTP::Post.new("/scans/#{scan_id}/stop")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      resp = JSON.parse(resp.body)
      return resp
    end

    def policy_delete(policy_id)
      request = Net::HTTP::Delete.new("/policies/#{policy_id}")
      request.add_field("X-Cookie",@token)
      resp = @connection.request(request)
      return resp.code
    end
  end
end
