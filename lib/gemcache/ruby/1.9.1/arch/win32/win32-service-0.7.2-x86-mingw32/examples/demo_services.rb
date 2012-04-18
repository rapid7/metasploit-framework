#######################################################################
# demo_services.rb
#
# Test script for general futzing that shows off the basic
# capabilities of this library. Modify as you see fit.
#
# You can run this sample program via the "example:services" task.
#######################################################################
require 'win32/service'
include Win32

puts "VERSION: " + Service::VERSION

p Service.exists?('Schedule')
p Service.exists?('bogusxxx')

status = Service.status('Schedule')
p status

info = Service.config_info('Schedule')

print "\n\nShowing config info for Schedule service\n\n"
p info

print "\n\nAbout to show all services\n\n"
sleep 10

Service.services{ |struct|
  p struct
}
