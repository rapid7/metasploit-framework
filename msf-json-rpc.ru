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
