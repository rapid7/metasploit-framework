require 'net/http'
require 'msf/core/db_manager/http/servlet_helper'

class SNSHandler
  include ServletHelper

  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)
    # puts "Received #{env['REQUEST_METHOD']} for path #{env['REQUEST_PATH']}"
    sns_message_type = env['HTTP_X_AMZ_SNS_MESSAGE_TYPE']
    if (request.post? and not sns_message_type.nil?)
      case sns_message_type
        when "Notification"
          env['rack.input'] = get_message_io(request)
        when "SubscriptionConfirmation"
          do_confirm(request)
          return [200, {}, ['']]
      end
    end

    @app.call(env)
  end

  #######
  private
  #######

  # Confirms SNS subscription
  def do_confirm(request)
    opts = parse_json_request(request, true)
    subscription_url = opts[:SubscribeURL]
    begin
      Net::HTTP.get(URI(subscription_url))
    rescue Exception => e
      puts "Error on subscription: #{e.message}"
    end
  end

  def get_message_io(request)
    opts = parse_json_request(request, true)
    message = opts[:Message]
    return StringIO.new(message)
  end
end