#!/usr/bin/env ruby
# coding: utf-8
# = nessus_rest.rb: communicate with Nessus(6+) over JSON REST interface
#
# Author:: Vlatko Kosturjak
#
# (C) Vlatko Kosturjak, Kost. Distributed under MIT license.
# 
# == What is this library? 
# 
# This library is used for communication with Nessus over JSON REST interface. 
# You can start, stop, pause and resume scan. Watch progress and status of scan, 
# download report, etc.
#
# == Requirements
# 
# Required libraries are standard Ruby libraries: uri, net/https and json. 
#
# == Usage:
# 
#   require 'nessus_rest'
#
#   n=NessusREST::Client.new ({:url=>'https://localhost:8834', :username=>'user', :password=> 'password'})
#   qs=n.scan_quick_template('basic','name-of-scan','localhost')
#   scanid=qs['scan']['id']
#   n.scan_wait4finish(scanid)
#   n.report_download_file(scanid,'csv','myscanreport.csv')
#

require 'openssl'
require 'uri'
require 'net/http'
require 'net/https'
require 'json'

# NessusREST module - for all stuff regarding Nessus REST JSON
# 

module NessusREST
  # Client class implementation of Nessus (6+) JSON REST protocol. 
  # Class which uses standard JSON lib to parse nessus JSON REST replies. 
  # 
  # == Typical Usage:
  #
  #   require 'nessus_rest'
  #
  #   n=NessusREST::Client.new ({:url=>'https://localhost:8834', :username=>'user', :password=> 'password'})
  #   qs=n.scan_quick_template('basic','name-of-scan','localhost')
  #   scanid=qs['scan']['id']
  #   n.scan_wait4finish(scanid)
  #   n.report_download_file(scanid,'csv','myscanreport.csv')
  #
  class Client
    attr_accessor :quick_defaults
    attr_accessor :defsleep, :httpsleep, :httpretry, :ssl_use, :ssl_verify, :autologin
    attr_reader :x_cookie

    class << self
      @connection
      @token
    end

    # initialize quick scan defaults: these will be used when not specifying defaults
    #
    # Usage: 
    # 
    #  n.init_quick_defaults()
    def init_quick_defaults
      @quick_defaults=Hash.new
      @quick_defaults['enabled']=false
      @quick_defaults['launch']='ONETIME'
      @quick_defaults['launch_now']=true
      @quick_defaults['description']='Created with nessus_rest'
    end
     
    # initialize object: try to connect to Nessus Scanner using URL, user and password
    # (or any other defaults)
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    def initialize(params={})
      # defaults
      @nessusurl = params.fetch(:url,'https://127.0.0.1:8834/')
      @username = params.fetch(:username,'nessus')
      @password = params.fetch(:password,'nessus')
      @ssl_verify = params.fetch(:ssl_verify,false)
      @ssl_use = params.fetch(:ssl_use,true)
      @autologin = params.fetch(:autologin, true)
      @defsleep = params.fetch(:defsleep, 1)
      @httpretry = params.fetch(:httpretry, 3)
      @httpsleep = params.fetch(:httpsleep, 1)

      init_quick_defaults()

      uri = URI.parse(@nessusurl)
      @connection = Net::HTTP.new(uri.host, uri.port)
      @connection.use_ssl = @ssl_use

      if @ssl_verify
        @connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
      else
        @connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
        
      yield @connection if block_given?
        authenticate(@username, @password) if @autologin
    end
 
    # Tries to authenticate to the Nessus REST JSON interface
    #
    # returns: true if logged in, false if not
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :autologin=>false)
    #  if n.authenticate('user','pass')
    #	puts "Logged in"
    #  else
    #	puts "Error"
    #  end
    def authenticate(username, password)
      @username = username
      @password = password
      authdefault
    end
    alias_method :login, :authenticate

    # Tries to authenticate to the Nessus REST JSON interface
    #
    # returns: true if logged in, false if not
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :autologin=>false, 
    #     :username=>'nessususer', :password=>'nessuspassword')
    #  if n.authdefault
    #	puts "Logged in"
    #  else
    #	puts "Error"
    #  end
    def authdefault
      payload = {
        :username => @username,
        :password => @password,
        :json => 1,
        :authenticationmethod => true
      }
      res = http_post(:uri=>"/session", :data=>payload)
      if res['token']
        @token = "token=#{res['token']}"
        @x_cookie = {'X-Cookie'=>@token}
        return true
      else
        false
      end
    end

    # checks if we're logged in correctly
    #
    # returns: true if logged in, false if not
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  if n.authenticated
    #	puts "Logged in"
    #  else
    #	puts "Error"
    #  end
    def authenticated
      if (@token && @token.include?('token='))
        return true
      else
        return false
      end
    end

    # try to get server properties
    #
    # returns: JSON parsed object with server properties
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.get_server_properties
    def get_server_properties
      http_get(:uri=>"/server/properties", :fields=>x_cookie)
    end
    alias_method :server_properties, :get_server_properties
  
    # Add user to server
    #
    # returns: JSON parsed object
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.user_add('user','password','16','local')
    #
    # Reference:
    # https://localhost:8834/api#/resources/users/create
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
      
    # delete user with user_id
    #
    # returns: result code
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  puts n.user_delete(1)
    def user_delete(user_id)
      res = http_delete(:uri=>"/users/#{user_id}", :fields=>x_cookie)
      return res.code
    end
      
    # change password for user_id
    #
    # returns: result code
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  puts n.user_chpasswd(1,'newPassword')
    def user_chpasswd(user_id, password)
      payload = {
        :password => password, 
        :json => 1
      }
      res = http_put(:uri=>"/users/#{user_id}/chpasswd", :data=>payload, :fields=>x_cookie)
      return res.code
    end
      
    # logout from the server
    #
    # returns: result code
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  puts n.user_logout
    def user_logout
      res = http_delete(:uri=>"/session", :fields=>x_cookie)
      return res.code
    end
    alias_method :logout, :user_logout

    # Get List of Policies
    #
    # returns: JSON parsed object with list of policies
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.list_policies
    def list_policies
      http_get(:uri=>"/policies", :fields=>x_cookie)
    end

    # Get List of Users
    #
    # returns: JSON parsed object with list of users
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.list_users
    def list_users
      http_get(:uri=>"/users", :fields=>x_cookie)
    end

    # Get List of Folders
    #
    # returns: JSON parsed object with list of folders
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.list_folders
    def list_folders
      http_get(:uri=>"/folders", :fields=>x_cookie)
    end

    # Get List of Scanners
    #
    # returns: JSON parsed object with list of scanners
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.list_scanners
    def list_scanners
      http_get(:uri=>"/scanners", :fields=>x_cookie)
    end

    # Get List of Families
    #
    # returns: JSON parsed object with list of families
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.list_families
    def list_families
      http_get(:uri=>"/plugins/families", :fields=>x_cookie)
    end

    # Get List of Plugins
    #
    # returns: JSON parsed object with list of plugins
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.list_plugins
    def list_plugins(family_id)
      http_get(:uri=>"/plugins/families/#{family_id}", :fields=>x_cookie)
    end

    # Get List of Templates
    #
    # returns: JSON parsed object with list of templates
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.list_templates
    def list_templates(type)
      res = http_get(:uri=>"/editor/#{type}/templates", :fields=>x_cookie)
    end

    def plugin_details(plugin_id)
      http_get(:uri=>"/plugins/plugin/#{plugin_id}", :fields=>x_cookie)
    end

    # check if logged in user is administrator
    #
    # returns: boolean value depending if user is administrator or not
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  if n.is_admin
    #	puts "Administrator"
    #  else
    #	puts "NOT administrator"
    #  end
    def is_admin
      res = http_get(:uri=>"/session", :fields=>x_cookie)
      if res['permissions'] == 128
        return true
      else
        return false
      end
    end

    # Get server status
    #
    # returns: JSON parsed object with server status
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.server_status
    def server_status
      http_get(:uri=>"/server/status", :fields=>x_cookie)
    end

    def scan_create(uuid, settings)
      payload = {
	:uuid => uuid, 
	:settings => settings,
	:json => 1
      }.to_json
      http_post(:uri=>"/scans", :body=>payload, :fields=>x_cookie, :ctype=>'application/json')
    end

    def scan_launch(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/launch", :fields=>x_cookie)
    end

    # Get List of Scans
    #
    # returns: JSON parsed object with list of scans
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.scan_list
    def scan_list
      http_get(:uri=>"/scans", :fields=>x_cookie)
    end
    alias_method :list_scans, :scan_list

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
      res = JSON.parse(res.body)
      return res
    end

    # delete scan with scan_id
    #
    # returns: boolean (true if deleted)
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  puts n.scan_delete(1)
    def scan_delete(scan_id)
      res = http_delete(:uri=>"/scans/#{scan_id}", :fields=>x_cookie)
      if res.code == 200 then
        return true
      end
      return false
    end

    def policy_delete(policy_id)
      res = http_delete(:uri=>"/policies/#{policy_id}", :fields=>x_cookie)
      return res.code
    end

    # Get template by type and uuid. Type can be 'policy' or 'scan'
    #
    # returns: JSON parsed object with template
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.editor_templates('scan',uuid)
    def editor_templates (type, uuid)
      res = http_get(:uri=>"/editor/#{type}/templates/#{uuid}", :fields=>x_cookie)
    end

    # Performs scan with templatename provided (name, title or uuid of scan).
    # Name is your scan name and targets are targets for scan
    #
    # returns: JSON parsed object with scan info
    #
    # Usage:
    #
    #   require 'nessus_rest'
    #
    #   n=NessusREST::Client.new ({:url=>'https://localhost:8834', :username=>'user', :password=> 'password'})
    #   qs=n.scan_quick_template('basic','name-of-scan','localhost')
    #   scanid=qs['scan']['id']
    #   n.scan_wait4finish(scanid)
    #   n.report_download_file(scanid,'csv','myscanreport.csv')
    #
    def scan_quick_template (templatename, name, targets)
      templates=list_templates('scan')['templates'].select do |temp| 
        temp['uuid'] == templatename or temp['name'] == templatename or temp['title'] == templatename
      end
      if templates.nil? then
        return nil
      end
      tuuid=templates.first['uuid']
      et=editor_templates('scan',tuuid)
      et.merge!(@quick_defaults)
      et['name']=name
      et['text_targets']=targets
      sc=scan_create(tuuid,et)
    end

    # Performs scan with scan policy provided (uuid of policy or policy name).
    # Name is your scan name and targets are targets for scan
    #
    # returns: JSON parsed object with scan info
    #
    # Usage:
    #
    #   require 'nessus_rest'
    #
    #   n=NessusREST::Client.new ({:url=>'https://localhost:8834', :username=>'user', :password=> 'password'})
    #   qs=n.scan_quick_policy('myscanpolicy','name-of-scan','localhost')
    #   scanid=qs['scan']['id']
    #   n.scan_wait4finish(scanid)
    #   n.report_download_file(scanid,'nessus','myscanreport.nessus')
    #
    def scan_quick_policy (policyname, name, targets)
      templates=list_policies['policies'].select do |pol|
        pol['template_uuid'] == policyname or pol['name'] == policyname
      end
      if templates.nil? then
	return nil
      end
      tuuid=templates.first['template_uuid']
      et=Hash.new
      et.merge!(@quick_defaults)
      et['name']=name
      et['text_targets']=targets
      sc=scan_create(tuuid,et)
    end

    def scan_status(scan_id)
      sd=scan_details(scan_id)
      if not sd['error'].nil?
        return 'error'
      end
      return sd['info']['status']
    end

    def scan_finished?(scan_id)
      ss=scan_status(scan_id)
      if ss == 'completed' or ss == 'canceled' or ss == 'imported' then
        return true
      end
      return false
    end

    def scan_wait4finish(scan_id)
      while not scan_finished?(scan_id) do
        # puts scan_status(scan_id)
        sleep @defsleep
      end
    end

    # Get host details from the scan
    #
    # returns: JSON parsed object with host details
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.host_detail(123, 1234)
    def host_detail(scan_id, host_id)
      res = http_get(:uri=>"/scans/#{scan_id}/hosts/#{host_id}", :fields=>x_cookie)
    end

    def report_download(scan_id, file_id)
      res = http_get(:uri=>"/scans/#{scan_id}/export/#{file_id}/download", :raw_content=> true, :fields=>x_cookie)
    end

    def report_download_quick(scan_id, format) 
      se=scan_export(scan_id,format)
      # ready, loading
      while (status = scan_export_status(scan_id,se['file'])['status']) != "ready" do
        # puts status
        if status.nil? or status == '' then
          return nil
        end
        sleep @defsleep
      end
      rf=report_download(scan_id,se['file'])
      return rf
    end

    def report_download_file(scan_id, format, outputfn)
      report_content=report_download_quick(scan_id, format)
      File.open(outputfn, 'w') do |f| 
        f.write(report_content)
      end
    end

    #
    # private?
    #

    # Perform HTTP put method with uri, data and fields
    #
    # returns: HTTP result object
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  payload = {
    #    :password => password, 
    #    :json => 1
    #  }
    #  res = n.http_put(:uri=>"/users/#{user_id}/chpasswd", :data=>payload, :fields=>n.x_cookie)
    #  puts res.code 
    def http_put(opts={})
      ret=http_put_low(opts)
      if ret.is_a?(Hash) and ret.has_key?('error') and ret['error']=='Invalid Credentials' then
	authdefault
	ret=http_put_low(opts)
	return ret
      else
	return ret
      end
    end

    def http_put_low(opts={})
      uri    = opts[:uri]
      data   = opts[:data]
      fields = opts[:fields] || {}
      res    = nil
      tries  = @httpretry

      req = Net::HTTP::Put.new(uri)
      req.set_form_data(data) unless (data.nil? || data.empty?)
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
	tries -= 1
        res = @connection.request(req)
      rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError => e
	if tries>0
	  sleep @httpsleep
	  retry
	else
	  return res
	end
      rescue URI::InvalidURIError
        return res
      end

      res
    end

    # Perform HTTP delete method with uri, data and fields
    #
    # returns: HTTP result object
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  res = n.http_delete(:uri=>"/session", :fields=>n.x_cookie)
    #  puts res.code
    def http_delete(opts={})
      ret=http_delete_low(opts)
      if ret.is_a?(Hash) and ret.has_key?('error') and ret['error']=='Invalid Credentials' then
	authdefault
	ret=http_delete_low(opts)
	return ret
      else
	return ret
      end
    end

    def http_delete_low(opts={})
      uri    = opts[:uri]
      fields = opts[:fields] || {}
      res    = nil
      tries  = @httpretry

      req = Net::HTTP::Delete.new(uri)

      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
	tries -= 1
        res = @connection.request(req)
      rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError => e
	if tries>0
	  sleep @httpsleep
	  retry
	else
	  return res
	end
      rescue URI::InvalidURIError
        return res
      end

      res
    end

    # Perform HTTP get method with uri and fields
    #
    # returns: JSON parsed object (if JSON parseable)
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.http_get(:uri=>"/users", :fields=>n.x_cookie)
    def http_get(opts={})
      raw_content = opts[:raw_content] || false
      ret=http_get_low(opts)
      if !raw_content then
	if ret.is_a?(Hash) and ret.has_key?('error') and ret['error']=='Invalid Credentials' then
          authdefault
          ret=http_get_low(opts)
          return ret
        else
          return ret
	end
      else
	return ret
      end
    end

    def http_get_low(opts={})
      uri    = opts[:uri]
      fields = opts[:fields] || {}
      raw_content = opts[:raw_content] || false
      json   = {}
      tries  = @httpretry

      req = Net::HTTP::Get.new(uri)
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        tries -= 1
        res = @connection.request(req)
      rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError => e
        if tries>0
          sleep @httpsleep
          retry
        else
          return json
        end
      rescue URI::InvalidURIError
        return json
      end
      if !raw_content
        parse_json(res.body)
      else
        res.body
      end
    end

    # Perform HTTP post method with uri, data, body and fields
    #
    # returns: JSON parsed object (if JSON parseable)
    #
    # Usage:
    #
    #  n=NessusREST::Client.new (:url=>'https://localhost:8834', :username=>'user', :password=> 'password')
    #  pp n.http_post(:uri=>"/scans/#{scan_id}/launch", :fields=>n.x_cookie)
    def http_post(opts={})
      if opts.has_key?(:authenticationmethod) then
        # i know authzmethod = opts.delete(:authorizationmethod) is short, but not readable
        authzmethod = opts[:authenticationmethod]
        opts.delete(:authenticationmethod)
      end
      ret=http_post_low(opts)
      if ret.is_a?(Hash) and ret.has_key?('error') and ret['error']=='Invalid Credentials' then
	if not authzmethod
          authdefault
	  ret=http_post_low(opts)
	  return ret
        end
      else
	return ret
      end
    end

    def http_post_low(opts={})
      uri    = opts[:uri]
      data   = opts[:data]
      fields = opts[:fields] || {}
      body   = opts[:body]
      ctype  = opts[:ctype]
      json   = {}
      tries  = @httpretry

      req = Net::HTTP::Post.new(uri)
      req.set_form_data(data) unless (data.nil? || data.empty?)
      req.body = body unless (body.nil? || body.empty?)
      req['Content-Type'] = ctype unless (ctype.nil? || ctype.empty?)
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
	tries -= 1
        res = @connection.request(req)
      rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError => e
	if tries>0
          sleep @httpsleep
	  retry
	else
	  return json
	end
      rescue URI::InvalidURIError
        return json
      end

      parse_json(res.body)
    end

    # Perform JSON parsing of body
    #
    # returns: JSON parsed object (if JSON parseable)
    #
    def parse_json(body)
      buf = {}

      begin
        buf = JSON.parse(body)
      rescue JSON::ParserError
      end

      buf
    end

  end # of Client class
end # of NessusREST module

