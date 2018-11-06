# encoding: utf-8

module Nexpose
  # Accessor to the Nexpose AJAX API.
  # These core methods should allow direct access to underlying controllers
  # in order to test functionality that is not currently exposed
  # through the XML API.
  #
  module AJAX
    module_function

    API_PATTERN = %r{/api/(?<version>[\d\.]+)}
    private_constant :API_PATTERN

    # Content type strings acceptect by Nexpose.
    #
    module CONTENT_TYPE
      XML  = 'text/xml; charset=UTF-8'
      JSON = 'application/json; charset-utf-8'
      FORM = 'application/x-www-form-urlencoded; charset=UTF-8'
    end

    # GET call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String] content_type Content type to use when issuing the GET.
    # @param [Hash] options Parameter options to the call.
    # @return [String|REXML::Document|Hash] The response from the call.
    #
    def get(nsc, uri, content_type = CONTENT_TYPE::XML, options = {})
      parameterize_uri(uri, options)
      get = Net::HTTP::Get.new(uri)
      get.set_content_type(content_type)
      request(nsc, get)
    end

    # PUT call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String|REXML::Document] payload XML document required by the call.
    # @param [String] content_type Content type to use when issuing the PUT.
    # @return [String] The response from the call.
    #
    def put(nsc, uri, payload = nil, content_type = CONTENT_TYPE::XML)
      put = Net::HTTP::Put.new(uri)
      put.set_content_type(content_type)
      put.body = payload.to_s if payload
      request(nsc, put)
    end

    # POST call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String|REXML::Document] payload XML document required by the call.
    # @param [String] content_type Content type to use when issuing the POST.
    # @param [Fixnum] timeout Set an explicit timeout for the HTTP request.
    # @return [String|REXML::Document|Hash] The response from the call.
    #
    def post(nsc, uri, payload = nil, content_type = CONTENT_TYPE::XML, timeout = nil)
      post = Net::HTTP::Post.new(uri)
      post.set_content_type(content_type)
      post.body = payload.to_s if payload
      request(nsc, post, timeout)
    end

    # PATCH call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String|REXML::Document] payload XML document required by the call.
    # @param [String] content_type Content type to use when issuing the PATCH.
    # @return [String] The response from the call.
    #
    def patch(nsc, uri, payload = nil, content_type = CONTENT_TYPE::XML)
      patch = Net::HTTP::Patch.new(uri)
      patch.set_content_type(content_type)
      patch.body = payload.to_s if payload
      request(nsc, patch)
    end

    # POST call to a Nexpose controller that uses a form-post model.
    # This is here to support legacy use of POST in old controllers.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [Hash] parameters Hash of attributes that need to be sent
    #    to the controller.
    # @param [String] content_type Content type to use when issuing the POST.
    # @return [Hash] The parsed JSON response from the call.
    #
    def form_post(nsc, uri, parameters, content_type = CONTENT_TYPE::FORM)
      post = Net::HTTP::Post.new(uri)
      post.set_content_type(content_type)
      post.set_form_data(parameters)
      request(nsc, post)
    end

    # DELETE call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String] content_type Content type to use when issuing the DELETE.
    def delete(nsc, uri, content_type = CONTENT_TYPE::XML)
      delete = Net::HTTP::Delete.new(uri)
      delete.set_content_type(content_type)
      request(nsc, delete)
    end

    ###
    # === Internal helper methods below this line. ===
    #
    # These are internal utility methods, not subject to backward compatibility
    # concerns.
    ###

    # Append the query parameters to given URI.
    #
    # @param [String] uri Controller address relative to https://host:port
    # @param [Hash] parameters Hash of attributes that need to be sent
    #    to the controller.
    # @return [Hash] The parameterized URI.
    #
    def parameterize_uri(uri, parameters)
      params = Hash.try_convert(parameters)
      unless params.nil? || params.empty?
        uri = uri.concat(('?').concat(parameters.map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join('&')))
      end
      uri
    end

    # Use the Nexpose::Connection to establish a correct HTTPS object.
    def https(nsc, timeout = nil)
      http = Net::HTTP.new(nsc.host, nsc.port)
      http.read_timeout = (timeout || nsc.timeout)
      http.open_timeout = nsc.open_timeout
      http.use_ssl = true
      if nsc.trust_store.nil?
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      else
        http.cert_store = nsc.trust_store
      end
      http
    end

    # Attach necessary header fields.
    def headers(nsc, request)
      request.add_field('nexposeCCSessionID', nsc.session_id)
      request.add_field('Cookie', "nexposeCCSessionID=#{nsc.session_id}")
    end

    def request(nsc, request, timeout = nil)
      http = https(nsc, timeout)
      headers(nsc, request)

      # Return response body if request is successful. Brittle.
      response = http.request(request)
      case response
      when Net::HTTPOK, Net::HTTPCreated, Net::HTTPNoContent
        response.body
      when Net::HTTPForbidden
        raise Nexpose::PermissionError.new(response)
      when Net::HTTPFound
        if response.header['location'] =~ /login/
          raise Nexpose::AuthenticationFailed.new(response)
        else
          raise get_api_error(request, response)
        end
      else
        raise get_api_error(request, response)
      end
    end

    def get_api_error(request, response)
      req_type = request.class.name.split('::').last.upcase
      error_message = get_error_message(request, response)
      Nexpose::APIError.new(response, "#{req_type} request to #{request.path} failed. #{error_message}", response.code)
    end

    # Get the version of the api target by request
    #
    # @param [HTTPRequest] request
    def get_request_api_version(request)
      matches = request.path.match(API_PATTERN)
      matches[:version].to_f
    rescue
      0.0
    end

    # Get an error message from the response body if the request url api version
    # is 2.1 or greater otherwise use the request body
    def get_error_message(request, response)
      version         = get_request_api_version(request)
      data_request    = use_response_error_message?(request, response)
      return_response = (version >= 2.1 || data_request)
      (return_response && response.body) ? "response body: #{response.body}" : "request body: #{request.body}"
    end

    # Code cleanup to allow for cleaner get_error_message method
    #
    def use_response_error_message?(request, response)
      if (request.path.include?('/data/') && !response.content_type.nil?)
        response.content_type.include? 'text/plain'
      else
        false
      end
    end

    # Execute a block of code while presenving the preferences for any
    # underlying table being accessed. Use this method when accessing data
    # tables which are present in the UI to prevent existing row preferences
    # from being set to 500.
    #
    # This is an internal utility method, not subject to backward compatibility
    # concerns.
    #
    # @param [Connection] nsc Live connection to a Nepose console.
    # @param [String] pref Preference key value to preserve.
    #
    def preserving_preference(nsc, pref)
      orig = get_rows(nsc, pref)
      yield
    ensure
      set_rows(nsc, pref, orig)
    end

    # Get a valid row preference value.
    #
    # This is an internal utility method, not subject to backward compatibility
    # concerns.
    #
    # @param [Fixnum] val Value to get inclusive row preference for.
    # @return [Fixnum] Valid row preference.
    #
    def row_pref_of(val)
      if val.nil? || val > 100
        500
      elsif val > 50
        100
      elsif val > 25
        50
      elsif val > 10
        25
      else
        10
      end
    end

    def get_rows(nsc, pref)
      uri      = '/data/user/preferences/all'
      pref_key = "#{pref}.rows"
      resp     = get(nsc, uri)
      json     = JSON.parse(resp)
      if json.key?(pref_key)
        rows = json[pref_key].to_i
        rows > 0 ? rows : 10
      else
        10
      end
    end

    def set_rows(nsc, pref, value)
      uri    = '/data/user/preference'
      params = { 'name' => "#{pref}.rows", 'value' => value }
      form_post(nsc, uri, params)
    end

  end
end
