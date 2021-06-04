# msf-json-rpc.ru
# Start using thin:
# thin --rackup msf-json-rpc.ru --address localhost --port 8081 --environment development --tag msf-json-rpc start
#

require 'pathname'
@framework_path = File.expand_path(File.dirname(__FILE__))
root = Pathname.new(@framework_path).expand_path
@framework_lib_path = root.join('lib')
$LOAD_PATH << @framework_lib_path unless $LOAD_PATH.include?(@framework_lib_path)

require 'msfenv'

if ENV['MSF_LOCAL_LIB']
  $LOAD_PATH << ENV['MSF_LOCAL_LIB'] unless $LOAD_PATH.include?(ENV['MSF_LOCAL_LIB'])
end

run Msf::WebServices::JsonRpcApp

#
# Ensure that framework is loaded before any external requests can be routed to the running
# application. This stops the possibility of the rack application being alive, but all
# requests failing.
#
warmup do |app|
  client = Rack::MockRequest.new(app)
  response = client.get('/api/v1/health')

  warmup_error_message = "Metasploit JSON RPC did not successfully start up. Unexpected response returned: '#{response.body}'"
  begin
    parsed_response = JSON.parse(response.body)
  rescue JSON::ParserError => e
    raise warmup_error_message, e
  end

  expected_response = { 'data' => { 'status' => 'UP' } }
  is_valid_response = parsed_response == expected_response

  unless is_valid_response
    raise warmup_error_message
  end
end
