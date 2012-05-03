############################################################################
# demo_daemon_ctl.rb
#
# This is a command line script for installing and/or running a small
# Ruby program as a service.  The service will simply write a small bit
# of text to a file every 20 seconds. It will also write some text to the
# file during the initialization (service_init) step.
#
# It should take about 10 seconds to start, which is intentional - it's a test
# of the service_init hook, so don't be surprised if you see "one moment,
# start pending" about 10 times on the command line.
#
# The file in question is C:\test.log.  Feel free to delete it when finished.
#
# To run the service, you must install it first.
#
# Usage: ruby demo_daemon_ctl.rb <option>
#
# Note that you *must* pass this program an option
#
# Options:
#    install    - Installs the service.  The service name is "DemoSvc"
#                 and the display name is "Demo".
#    start      - Starts the service.  Make sure you stop it at some point or
#                 you will eventually fill up your filesystem!.
#    stop       - Stops the service.
#    pause      - Pauses the service.
#    resume     - Resumes the service.
#    uninstall  - Uninstalls the service.
#    delete     - Same as uninstall.
#
# You can also used the Windows Services GUI to start and stop the service.
#
# To get to the Windows Services GUI just follow:
#    Start -> Control Panel -> Administrative Tools -> Services
############################################################################
require 'win32/service'
require 'rbconfig'
include Win32
include Config

# Make sure you're using the version you think you're using.
puts 'VERSION: ' + Service::VERSION

SERVICE_NAME = 'DemoSvc'
SERVICE_DISPLAYNAME = 'Demo'

# Quote the full path to deal with possible spaces in the path name.
ruby = File.join(CONFIG['bindir'], 'ruby').tr('/', '\\')
path = ' "' + File.dirname(File.expand_path($0)).tr('/', '\\')
path += '\demo_daemon.rb"'
cmd = ruby + path

# You must provide at least one argument.
raise ArgumentError, 'No argument provided' unless ARGV[0]

case ARGV[0].downcase
   when 'install'
      Service.new(
         :service_name     => SERVICE_NAME,
         :display_name     => SERVICE_DISPLAYNAME,
         :description      => 'Sample Ruby service',
         :binary_path_name => cmd
      )
      puts 'Service ' + SERVICE_NAME + ' installed'      
   when 'start'
      if Service.status(SERVICE_NAME).current_state != 'running'
         Service.start(SERVICE_NAME, nil, 'hello', 'world')
         while Service.status(SERVICE_NAME).current_state != 'running'
            puts 'One moment...' + Service.status(SERVICE_NAME).current_state
            sleep 1
         end
         puts 'Service ' + SERVICE_NAME + ' started'
      else
         puts 'Already running'
      end
   when 'stop'
      if Service.status(SERVICE_NAME).current_state != 'stopped'
         Service.stop(SERVICE_NAME)
         while Service.status(SERVICE_NAME).current_state != 'stopped'
            puts 'One moment...' + Service.status(SERVICE_NAME).current_state
            sleep 1
         end
         puts 'Service ' + SERVICE_NAME + ' stopped'
      else
         puts 'Already stopped'
      end
   when 'uninstall', 'delete'
      if Service.status(SERVICE_NAME).current_state != 'stopped'
         Service.stop(SERVICE_NAME)
      end
      while Service.status(SERVICE_NAME).current_state != 'stopped'
         puts 'One moment...' + Service.status(SERVICE_NAME).current_state
         sleep 1
      end
      Service.delete(SERVICE_NAME)
      puts 'Service ' + SERVICE_NAME + ' deleted'
   when 'pause'
      if Service.status(SERVICE_NAME).current_state != 'paused'
         Service.pause(SERVICE_NAME)
         while Service.status(SERVICE_NAME).current_state != 'paused'
            puts 'One moment...' + Service.status(SERVICE_NAME).current_state
            sleep 1
         end
         puts 'Service ' + SERVICE_NAME + ' paused'
      else
         puts 'Already paused'
      end
   when 'resume'
      if Service.status(SERVICE_NAME).current_state != 'running'
         Service.resume(SERVICE_NAME)
         while Service.status(SERVICE_NAME).current_state != 'running'
            puts 'One moment...' + Service.status(SERVICE_NAME).current_state
            sleep 1
         end
         puts 'Service ' + SERVICE_NAME + ' resumed'
      else
         puts 'Already running'
      end
   else
      raise ArgumentError, 'unknown option: ' + ARGV[0]
end
