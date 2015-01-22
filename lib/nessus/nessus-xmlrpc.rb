require 'faraday'
require 'cgi'
require 'json'
require 'nessus/client/file'
require 'nessus/client/policy'
require 'nessus/client/report'
require 'nessus/client/report2'
require 'nessus/client/scan'
require 'nessus/error'
require 'nessus/version'

module Nessus

   class Client
      include Nessus::Client::File
      include Nessus::Client::Policy
      include Nessus::Client::Report
      include Nessus::Client::Report2
      include Nessus::Client::Scan
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
         @connection = Faraday.new host, connection_options
         @connection.headers[:user_agent] = "Nessus.rb v#{Nessus::VERSION}".freeze

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
         resp = connection.post '/session', payload
         resp = JSON.parse(resp.body)
         #if resp['reply']['status'].eql? 'OK'
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
         resp = connection.get '/server/properties'
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
        resp = connection.post '/users', payload
        resp = JSON.parse(resp.body)
        return resp
      end

      def user_logout
         resp = connection.delete '/session'
         if resp.body.length > 1
            resp = JSON.parse(resp.body)
            puts "Respose of session deletion is #{resp}"
            return true
         else
            return false
         end
      end

      def list_policies
         resp = connection.get '/policies'
         resp = JSON.parse(resp.body)["policies"]
         return resp
      end

      def list_users
         resp = connection.get '/users'
         resp = JSON.parse(resp.body)["users"]
         return resp
      end

      def list_folders
         resp = connection.get '/folders'
         resp = JSON.parse(resp.body)["folders"]
         return resp
      end
    
      def is_admin
         resp = connection.get '/session'
         resp = JSON.parse(resp.body)
         if resp["permissions"] == 128
            return true
         else
            return false
         end
      end

      def server_properties
         resp = connection.get '/server/properties'
         resp = JSON.parse(resp.body)
         return resp
      end

      def server_status
         resp = connection.get '/server/status'
         resp = JSON.parse(resp.body)
         return resp
      end

      def scan_list
         resp = connection.get '/scans'
         resp = JSON.parse(resp.body)["scans"]
         return resp
      end

   end
end
