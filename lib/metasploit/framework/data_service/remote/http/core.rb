require 'metasploit/framework/data_service'
require 'metasploit/framework/data_service/remote/http/data_service_auto_loader'
require 'net/http'
require 'net/https'
require 'uri'

#
# Parent data service for managing metasploit data in/on a separate process/machine over HTTP(s)
#
module Metasploit
module Framework
module DataService
class RemoteHTTPDataService
  include Metasploit::Framework::DataService
  include DataServiceAutoLoader

  DEFAULT_USER_AGENT = "metasploit v#{Metasploit::Framework::VERSION}"

  EXEC_ASYNC = { :exec_async => true }
  GET_REQUEST = 'GET'
  POST_REQUEST = 'POST'
  DELETE_REQUEST = 'DELETE'
  PUT_REQUEST = 'PUT'

  attr_reader :endpoint, :https_opts, :api_token

  #
  # @param [String] endpoint A valid http or https URL. Cannot be nil
  #
  def initialize(endpoint, opts = {})
    validate_endpoint(endpoint)
    @endpoint = URI.parse(endpoint)
    @https_opts = opts[:https_opts]
    @api_token = opts[:api_token]

    @headers = {}
    user_agent = !opts[:user_agent].nil? ? opts[:user_agent] : DEFAULT_USER_AGENT
    set_header('User-Agent', user_agent)
    set_header('Authorization', "Bearer #{@api_token}") unless @api_token.nil?

    build_client_pool(5)
  end

  def connection_established?
    true
  end

  def after_establish_connection

  end

  def name
    "remote_data_service: (#{@endpoint})"
  end

  def active
    # checks if data service is online when @active is falsey and makes the assignment
    # this is to prevent repetitive calls to check if data service is online
    # logic should be enhanced to considering data service connectivity
    # and future data service implementations
    @active ||= is_online?
  end

  def active=(value)
    @active = value
  end

  def is_local?
    false
  end

  def error
    'none'
  end

  def driver
    'http'
  end

  #
  # POST data to the HTTP endpoint and don't wait for the endpoint to process the data before getting a response
  #
  # @param path - The URI path to send the request
  # @param data_hash - A hash representation of the object to be posted. Cannot be nil or empty.
  # @param query - A hash representation of the URI query data. Key-value pairs will be URL-encoded.
  #
  # @return A wrapped response (ResponseWrapper), see below.
  #
  def post_data_async(path, data_hash, query = nil)
    make_request(POST_REQUEST, path, data_hash.merge(EXEC_ASYNC), query)
  end

  #
  # POST data to the HTTP endpoint
  #
  # @param path - The URI path to send the request
  # @param data_hash - A hash representation of the object to be posted. Cannot be nil or empty.
  # @param query - A hash representation of the URI query data. Key-value pairs will be URL-encoded.
  #
  # @return A wrapped response (ResponseWrapper), see below.
  #
  def post_data(path, data_hash, query = nil)
    make_request(POST_REQUEST, path, data_hash, query)
  end

  #
  # GET data from the HTTP endpoint
  #
  # @param path - The URI path to send the request
  # @param data_hash - A hash representation of the object to be included. Can be nil or empty.
  # @param query - A hash representation of the URI query data. Key-value pairs will be URL-encoded.
  #
  # @return A wrapped response (ResponseWrapper), see below.
  #
  def get_data(path, data_hash = nil, query = nil)
    make_request(GET_REQUEST, path, data_hash, query)
  end

  #
  # Send DELETE request to delete the specified resource from the HTTP endpoint
  #
  # @param path - The URI path to send the request
  # @param data_hash - A hash representation of the object to be deleted. Cannot be nil or empty.
  # @param query - A hash representation of the URI query data. Key-value pairs will be URL-encoded.
  #
  # @return A wrapped response (ResponseWrapper), see below.
  #
  def delete_data(path, data_hash, query = nil)
    make_request(DELETE_REQUEST, path, data_hash, query)
  end

  #
  # Send PUT request to store data for the specified resource at the HTTP endpoint
  #
  # @param path - The URI path to send the request
  # @param data_hash - A hash representation of the object to be stored. Cannot be nil or empty.
  # @param query - A hash representation of the URI query data. Key-value pairs will be URL-encoded.
  #
  # @return A wrapped response (ResponseWrapper), see below.
  #
  def put_data(path, data_hash, query = nil)
    make_request(PUT_REQUEST, path, data_hash, query)
  end

  #
  # Make the specified request_type
  #
  # @param request_type - A string representation of the HTTP method
  # @param path - The URI path to send the request
  # @param data_hash - A hash representation of the object to be included in the request. Cannot be nil or empty.
  # @param query - A hash representation of the URI query data. Key-value pairs will be URL-encoded.
  #
  # @return A wrapped response (ResponseWrapper)
  #
  def make_request(request_type, path, data_hash = nil, query = nil)
    begin
      # simplify query by removing nil values
      query_str = (!query.nil? && !query.empty?) ? query.compact.to_query : nil
      uri = URI::HTTP::build({path: path, query: query_str})
      # TODO: Re-enable this logging when framework handles true log levels.
      #dlog("HTTP #{request_type} request to #{uri.request_uri} with #{data_hash ? data_hash : "nil"}")

      client = @client_pool.pop
      case request_type
        when GET_REQUEST
          request = Net::HTTP::Get.new(uri.request_uri, initheader=@headers)
        when POST_REQUEST
          request = Net::HTTP::Post.new(uri.request_uri, initheader=@headers)
        when DELETE_REQUEST
          request = Net::HTTP::Delete.new(uri.request_uri, initheader=@headers)
        when PUT_REQUEST
          request = Net::HTTP::Put.new(uri.request_uri, initheader=@headers)
        else
          raise Exception, 'A request_type must be specified'
      end
      built_request = build_request(request, data_hash)
      response = client.request(built_request)

      case response
        when Net::HTTPOK
          return SuccessResponse.new(response)
        else
          ilog "HTTP #{request_type} request: #{uri.request_uri} failed with code: #{response.code} message: #{response.body}"
          return ErrorResponse.new(response)
      end
    rescue EOFError => e
      error_msg = "No data was returned from the data service for request type/path : #{request_type}/#{path}, message: #{e.message}"
      ilog error_msg
      return FailedResponse.new(error_msg)
    rescue => e
      error_msg = "Problem with HTTP request for type/path: #{request_type}/#{path} message: #{e.message}"
      ilog error_msg
      return FailedResponse.new(error_msg)
    ensure
      @client_pool << client
    end
  end

  def set_header(key, value)
    @headers[key] = value
  end

  #
  # Checks if the data service is online by making a request
  # for the Metasploit version number from the remote endpoint
  #
  def is_online?
    response = self.get_msf_version
    if response && !response[:metasploit_version].empty?
      return true
    end

    return false
  end

  # Select the correct path for GET request based on the options parameters provided.
  # If 'id' is present, the user is requesting a single record and should use
  # api/<version>/<resource>/ID path.
  #
  # @param [Hash] opts The parameters for the request
  # @param [String] path The base resource path for the endpoint
  #
  # @return [String] The correct path for the request.
  def get_path_select(opts, path)
    if opts.key?(:id)
      path = "#{path}/#{opts[:id]}"
      opts.delete(:id)
    end
    path
  end

  #########
  protected
  #########

  #
  # Simple response wrapper
  #
  class ResponseWrapper
    attr_reader :response

    def initialize(response)
      @response = response
    end

    def response_body
      if @response
        @response.body
      else
        nil
      end
    end

    def to_s
      if @response
        @response.to_s
      else
        ''
      end
    end
  end

  #
  # Error response wrapper
  # There is a response object, however, the request was unsuccessful.
  #
  class ErrorResponse < ResponseWrapper
    def initialize(response)
      super(response)
    end
  end

  #
  # Failed response wrapper
  # There is no response object.
  #
  class FailedResponse < ErrorResponse
    attr_reader :error_msg

    def initialize(error_msg)
      @error_msg = error_msg
      super(nil)
    end

    def to_s
      return error_msg
    end
  end

  #
  # Success response wrapper
  #
  class SuccessResponse < ResponseWrapper
    def initialize(response)
      super(response)
    end
  end

  #######
  private
  #######

  def validate_endpoint(endpoint)
    raise 'Endpoint cannot be nil' if endpoint.nil?
  end

  def build_request(request, data_hash)
    request.content_type = 'application/json'
    if !data_hash.nil? && !data_hash.empty?
      data_hash.each do |k,v|
        if v.is_a?(Msf::Session)
          dlog('Dropping Msf::Session object before converting to JSON.')
          dlog("data_hash is #{data_hash}")
          dlog('Callstack:')
          caller.each { |line| dlog("#{line}\n")}
          data_hash.delete(k)
        end
      end
      json_body = data_hash.to_json
      request.body = json_body
    end

    request
  end

  def build_client_pool(size)
    @client_pool = Queue.new()
    (1..size).each {
      http = Net::HTTP.new(@endpoint.host, @endpoint.port)
      if @endpoint.is_a?(URI::HTTPS)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        if @https_opts && !@https_opts.empty?
          if @https_opts[:skip_verify]
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          else
            # https://stackoverflow.com/questions/22093042/implementing-https-certificate-pubkey-pinning-with-ruby
            user_passed_cert = OpenSSL::X509::Certificate.new(File.read(@https_opts[:cert]))

            http.verify_callback = lambda do |preverify_ok, cert_store|
              server_cert = cert_store.chain[0]
              return true unless server_cert.to_der == cert_store.current_cert.to_der
              same_public_key?(server_cert, user_passed_cert)
            end
          end
        end
      end
      @client_pool << http
    }
  end

  # Tells us whether the private keys on the passed certificates match
  # and use the same algo
  def same_public_key?(ref_cert, actual_cert)
    pkr, pka = ref_cert.public_key, actual_cert.public_key

    # First check if the public keys use the same crypto...
    return false unless pkr.class == pka.class
    # ...and then - that they have the same contents
    return false unless pkr.to_pem == pka.to_pem

    true
  end

end
end
end
end

