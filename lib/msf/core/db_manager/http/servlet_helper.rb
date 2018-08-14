require 'json'
require 'msf/core/db_manager/http/db_manager_proxy'
require 'msf/core/db_manager/http/job_processor'
require 'metasploit/framework/data_service/remote/http/response_data_helper'
require 'rex/ui/text/output/stdio'

module ServletHelper
  include ResponseDataHelper

  @@console_printer = Rex::Ui::Text::Output::Stdio.new

  def set_error_on_response(error)
    print_error "Error handling request: #{error.message}", error
    headers = {'Content-Type' => 'text/plain'}
    [500, headers, error.message]
  end

  def set_empty_response
    set_json_data_response(response: '')
  end

  def set_json_response(data, includes = nil, code = 200)
    headers = { 'Content-Type' => 'application/json' }
    [code, headers, to_json(data, includes)]
  end

  def set_json_data_response(response:, includes: nil, code: 200)
    data_response = { data: response }
    set_json_response(data_response, includes = includes, code = code)
  end

  def set_json_error_response(response:, code:)
    error_response = { error: response }
    set_json_response(error_response, nil, code = code)
  end

  def set_html_response(data)
    headers = {'Content-Type' => 'text/html'}
    [200, headers, data]
  end

  def parse_json_request(request, strict = false)
    body = request.body.read
    if (body.nil? || body.empty?)
      raise 'Invalid body, expected data' if strict
      return {}
    end

    hash = JSON.parse(body)
    hash.deep_symbolize_keys
  end

  def print_error_and_create_response(error: , message:, code:)
    print_error "Error handling request: #{error.message}.", error
    error_response = {
        code: code,
        message: "#{message} #{error.message}"
    }
    set_json_error_response(response: error_response, code: code)
  end

  def exec_report_job(request, includes = nil, &job)
    begin

      # report jobs always need data
      opts = parse_json_request(request, true)

      exec_async = opts.delete(:exec_async)
      if (exec_async)
        JobProcessor.instance.submit_job(opts, &job)
        return set_empty_response
      else
        data = job.call(opts)
        return set_json_data_response(response: data, includes: includes)
      end

    rescue => e
      print_error_and_create_response(error: e, message: 'There was an error creating the record:', code: 500)
    end
  end

  def get_db
    DBManagerProxy.instance.db
  end

  # Sinatra injects extra parameters for some reason: https://github.com/sinatra/sinatra/issues/453
  # This method cleans those up so we don't have any unexpected values before passing on.
  # It also inspects the query string for any invalid parameters.
  #
  # @param [Hash] params Hash containing the parameters for the request.
  # @param [Hash] query_hash The query_hash variable from the rack request.
  # @return [Hash] Returns params with symbolized keys and the injected parameters removed.
  def sanitize_params(params, query_hash = {})
    # Reject id passed as a query parameter for GET requests.
    # API standards say path ID should be used for single records.
    if query_hash.key?('id')
      raise ArgumentError, ("'id' is not a valid query parameter. Please use /api/v1/<resource>/{ID} instead.")
    end
    params.symbolize_keys.except(:captures, :splat)
  end

  # Determines if this data set should be output as a single object instead of an array.
  #
  # @param [Array] data Array containing the data to be returned to the user.
  # @param [Hash] params The parameters included in the request.
  #
  # @return [Bool] true if the data should be printed as a single object, false otherwise
  def is_single_object?(data, params)
    # Check to see if the ID parameter was present. If so, print as a single object.
    # Note that ID is not valid as a query parameter, so we assume that the user
    # used <resource>/{ID} notation if ID is present in params.
    !params[:id].nil? && data.count == 1
  end

  def format_cred_json(data)
    includes = [:logins, :public, :private, :realm, :origin]

    response = []
    Array.wrap(data).each do |cred|
      json = cred.as_json(include: includes)
      json['origin'] = json['origin'].merge('type' => cred.origin.class.to_s) if cred.origin
      json['public'] = json['public'].merge('type' => cred.public.type) if cred.public
      json['private'] = json['private'].merge('type' => cred.private.type) if cred.private
      response << json
    end
    response
  end

  # Get Warden::Proxy object from the Rack environment.
  # @return [Warden::Proxy] The Warden::Proxy object from the Rack environment.
  def warden
    env['warden']
  end

  # Get Warden options hash from the Rack environment.
  # @return [Hash] The Warden options hash from the Rack environment.
  def warden_options
    env['warden.options']
  end

  def print_line(msg)
    @@console_printer.print_line(msg)
  end

  def print_warning(msg)
    @@console_printer.print_warning(msg)
  end

  def print_good(msg)
    @@console_printer.print_good(msg)
  end

  def print_error(msg, exception = nil)
    unless exception.nil?
      msg += "\n    Call Stack:"
      exception.backtrace.each {|line|
        msg += "\n"
        msg += "\t #{line}"
      }
    end

    @@console_printer.print_error(msg)
  end


  #######
  private
  #######

  def to_json(data, includes = nil)
    return '{}' if data.nil?
    json = includes.nil? ? data.to_json : data.to_json(include:  includes)
    return json.to_s
  end


  # TODO: add query meta
  # Returns a hash representing the model. Some configuration can be
  # passed through +options+.
  #
  # The option <tt>include_root_in_json</tt> controls the top-level behavior
  # of +as_json+. If +true+, +as_json+ will emit a single root node named
  # after the object's type. The default value for <tt>include_root_in_json</tt>
  # option is +false+.
  #
  #   user = User.find(1)
  #   user.as_json
  #   # => { "id" => 1, "name" => "Konata Izumi", "age" => 16,
  #   #     "created_at" => "2006/08/01", "awesome" => true}
  #
  #   ActiveRecord::Base.include_root_in_json = true
  #
  #   user.as_json
  #   # => { "user" => { "id" => 1, "name" => "Konata Izumi", "age" => 16,
  #   #                  "created_at" => "2006/08/01", "awesome" => true } }
  #
  # This behavior can also be achieved by setting the <tt>:root</tt> option
  # to +true+ as in:
  #
  #   user = User.find(1)
  #   user.as_json(root: true)
  #   # => { "user" => { "id" => 1, "name" => "Konata Izumi", "age" => 16,
  #   #                  "created_at" => "2006/08/01", "awesome" => true } }
  #
  # Without any +options+, the returned Hash will include all the model's
  # attributes.
  #
  #   user = User.find(1)
  #   user.as_json
  #   # => { "id" => 1, "name" => "Konata Izumi", "age" => 16,
  #   #      "created_at" => "2006/08/01", "awesome" => true}
  #
  # The <tt>:only</tt> and <tt>:except</tt> options can be used to limit
  # the attributes included, and work similar to the +attributes+ method.
  #
  #   user.as_json(only: [:id, :name])
  #   # => { "id" => 1, "name" => "Konata Izumi" }
  #
  #   user.as_json(except: [:id, :created_at, :age])
  #   # => { "name" => "Konata Izumi", "awesome" => true }
  #
  # To include the result of some method calls on the model use <tt>:methods</tt>:
  #
  #   user.as_json(methods: :permalink)
  #   # => { "id" => 1, "name" => "Konata Izumi", "age" => 16,
  #   #      "created_at" => "2006/08/01", "awesome" => true,
  #   #      "permalink" => "1-konata-izumi" }
  #
  # To include associations use <tt>:include</tt>:
  #
  #   user.as_json(include: :posts)
  #   # => { "id" => 1, "name" => "Konata Izumi", "age" => 16,
  #   #      "created_at" => "2006/08/01", "awesome" => true,
  #   #      "posts" => [ { "id" => 1, "author_id" => 1, "title" => "Welcome to the weblog" },
  #   #                   { "id" => 2, "author_id" => 1, "title" => "So I was thinking" } ] }
  #
  # Second level and higher order associations work as well:
  #
  #   user.as_json(include: { posts: {
  #                              include: { comments: {
  #                                             only: :body } },
  #                              only: :title } })
  #   # => { "id" => 1, "name" => "Konata Izumi", "age" => 16,
  #   #      "created_at" => "2006/08/01", "awesome" => true,
  #   #      "posts" => [ { "comments" => [ { "body" => "1st post!" }, { "body" => "Second!" } ],
  #   #                     "title" => "Welcome to the weblog" },
  #   #                   { "comments" => [ { "body" => "Don't think too hard" } ],
  #   #

end