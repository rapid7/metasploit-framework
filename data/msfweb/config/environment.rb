# Be sure to restart your web server when you modify this file.

# Uncomment below to force Rails into production mode when 
# you don't control web/app server and can't set it the proper way

ENV['RAILS_ENV'] = 'production'

# Specifies gem version of Rails to use when vendor/rails is not present
RAILS_GEM_VERSION = '1.2.2'

# Bootstrap the Rails environment, frameworks, and default configuration
require File.join(File.dirname(__FILE__), 'boot')

Rails::Initializer.run do |config|
  ActionController::Base.allow_concurrency = true
end


msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', '..', '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'

$msfweb      = Msf::Ui::Web::Driver.new({'LogLevel' => 5})
$msframework = $msfweb.framework

if ($browser_start)
	Thread.new do
		
		select(nil, nil, nil, 1)
		
		case RUBY_PLATFORM
		when /mswin32/
			system("start #{$browser_url}")
		when /darwin/
			system("open #{$browser_url}")
		else
			system("firefox #{$browser_url} &")
		end
	end
end
