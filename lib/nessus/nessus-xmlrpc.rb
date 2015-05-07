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
        :json => 1
      }
      res = http_post(:uri=>"/session", :data=>payload)
      if res['token']
        @token = "token=#{res['token']}"
        return true
      else
        false
      end
    end

    def x_cookie
      {'X-Cookie'=>@token}
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
      http_get(:uri=>"/server/properties", :fields=>x_cookie)
    end
  
    def user_add(username, password, permissions, type)
      payload = {
        :username => username, 
        :password => password, 
        :permissions => permissions, 
        :type => type, 
        :json => 1
      }
      http_post(:uri=>"/users", :fields=>x_cookie, :data=>payload)
    end
      
    def user_delete(user_id)
      res = http_delete(:uri=>"/users/#{user_id}", :fields=>x_cookie)
      return res.code
    end
      
    def user_chpasswd(user_id, password)
      payload = {
        :password => password, 
        :json => 1
      }
      res = http_put(:uri=>"/users/#{user_id}/chpasswd", :data=>payload, :fields=>x_cookie)
      return res.code
    end
      
    def user_logout
      res = http_delete(:uri=>"/session", :fields=>x_cookie)
      return res.code
    end

    def list_policies
      http_get(:uri=>"/policies", :fields=>x_cookie)
    end

    def list_users
      http_get(:uri=>"/users", :fields=>x_cookie)
    end

    def list_folders
      http_get(:uri=>"/folders", :fields=>x_cookie)
    end

    def list_scanners
      http_get(:uri=>"/scanners", :fields=>x_cookie)
    end

    def list_families
      http_get(:uri=>"/plugins/families", :fields=>x_cookie)
    end

    def list_plugins(family_id)
      http_get(:uri=>"/plugins/families/#{family_id}", :fields=>x_cookie)
    end

    def list_template(type)
      res = http_get(:uri=>"/editor/#{type}/templates", :fields=>x_cookie)
    end

    def plugin_details(plugin_id)
      http_get(:uri=>"/plugins/plugin/#{plugin_id}", :fields=>x_cookie)
    end

    def is_admin
      res = http_get(:uri=>"/session", :fields=>x_cookie)
      if res['permissions'] == 128
        return true
      else
        return false
      end
    end

    def server_properties
      http_get(:uri=>"/server/properties", :fields=>x_cookie)
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
      }.to_json
      http_post(:uri=>"/scans", :body=>payload, :fields=>x_cookie, :ctype=>'application/json')
    end

    def scan_launch(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/launch", :fields=>x_cookie)
    end

    def server_status
      http_get(:uri=>"/server/status", :fields=>x_cookie)
    end

    def scan_list
      http_get(:uri=>"/scans", :fields=>x_cookie)
    end

    def scan_details(scan_id)
      http_get(:uri=>"/scans/#{scan_id}", :fields=>x_cookie)
    end

    def scan_pause(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/pause", :fields=>x_cookie)
    end

    def scan_resume(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/resume", :fields=>x_cookie)
    end

    def scan_stop(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/stop", :fields=>x_cookie)
    end

    def scan_export(scan_id, format)
      payload = {
        :format => format
      }.to_json
      http_post(:uri=>"/scans/#{scan_id}/export", :body=>payload, :ctype=>'application/json', :fields=>x_cookie)
    end

    def scan_export_status(scan_id, file_id)
      request = Net::HTTP::Get.new("/scans/#{scan_id}/export/#{file_id}/status")
      request.add_field("X-Cookie", @token)
      res = @connection.request(request)
      if res.code == "200"
        return "ready"
      else
        res = JSON.parse(res.body)
        return res
      end
    end

    def policy_delete(policy_id)
      res = http_delete(:uri=>"/policies/#{policy_id}", :fields=>x_cookie)
      return res.code
    end

    def host_detail(scan_id, host_id)
      res = http_get(:uri=>"/scans/#{scan_id}/hosts/#{host_id}", :fields=>x_cookie)
    end

    def report_download(scan_id, file_id)
      res = http_get(:uri=>"/scans/#{scan_id}/export/#{file_id}/download", :raw_content=> true, :fields=>x_cookie)
    end

    private

    def http_put(opts={})
      uri    = opts[:uri]
      data   = opts[:data]
      fields = opts[:fields] || {}
      res    = nil

      req = Net::HTTP::Put.new(uri)
      req.set_form_data(data) unless data.blank?
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return res
      end

      res
    end

    def http_delete(opts={})
      uri    = opts[:uri]
      fields = opts[:fields] || {}
      res    = nil

      req = Net::HTTP::Delete.new(uri)

      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return res
      end

      res
    end

    def http_get(opts={})
      uri    = opts[:uri]
      fields = opts[:fields] || {}
      raw_content = opts[:raw_content] || false
      json   = {}

      req = Net::HTTP::Get.new(uri)
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return json
      end
      if !raw_content
        parse_json(res.body)
      else
        res.body
      end
    end

    def http_post(opts={})
      uri    = opts[:uri]
      data   = opts[:data]
      fields = opts[:fields] || {}
      body   = opts[:body]
      ctype  = opts[:ctype]
      json   = {}

      req = Net::HTTP::Post.new(uri)
      req.set_form_data(data) unless data.blank?
      req.body = body unless body.blank?
      req['Content-Type'] = ctype unless ctype.blank?
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return json
      end

      parse_json(res.body)
    end

    def parse_json(body)
      buf = {}

      begin
        buf = JSON.parse(body)
      rescue JSON::ParserError
      end

      buf
    end

  end
end
