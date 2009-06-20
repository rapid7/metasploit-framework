#
# Force the application into production mode
#
ENV['RAILS_ENV'] = 'production'

# Specifies gem version of Rails to use when vendor/rails is not present
RAILS_GEM_VERSION = '2.3.2' unless defined? RAILS_GEM_VERSION


msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.join(File.dirname(msfbase), '..', '..', '..','lib'))

#
# New versions of Rails force the KCODE to unicode. This breaks
# binary string generation used by Metasploit for shellcode,
# text generation, and encoding. We override the initialize_encoding
# method and force KCODE to be 'NONE'
#
class Rails::Initializer
	def initialize_encoding
		if (RUBY_VERSION !~ /^1\.9\./)
			$KCODE = 'NONE'
		end
	end
end


# Bootstrap the Rails environment, frameworks, and default configuration
require File.join(File.dirname(__FILE__), 'boot')

Rails::Initializer.run do |config|
	config.frameworks -= [ :active_record ]
	config.action_controller.session = 
		{ 
			:session_key => "_msfweb_session",
			:secret      => ::Rex::Text.rand_text_alphanumeric(30)
		}	

  # Settings in config/environments/* take precedence over those specified here.
  # Application configuration should go into files in config/initializers
  # -- all .rb files in that directory are automatically loaded.

  # Add additional load paths for your own custom dirs
  # config.load_paths += %W( #{RAILS_ROOT}/extras )

  # Specify gems that this application depends on and have them installed with rake gems:install
  # config.gem "bj"
  # config.gem "hpricot", :version => '0.6', :source => "http://code.whytheluckystiff.net"
  # config.gem "sqlite3-ruby", :lib => "sqlite3"
  # config.gem "aws-s3", :lib => "aws/s3"

  # Only load the plugins named here, in the order given (default is alphabetical).
  # :all can be used as a placeholder for all plugins not explicitly named
  # config.plugins = [ :exception_notification, :ssl_requirement, :all ]

  # Skip frameworks you're not going to use. To use Rails without a database,
  # you must remove the Active Record framework.
  # config.frameworks -= [ :active_record, :active_resource, :action_mailer ]

  # Activate observers that should always be running
  # config.active_record.observers = :cacher, :garbage_collector, :forum_observer

  # Set Time.zone default to the specified zone and make Active Record auto-convert to this zone.
  # Run "rake -D time" for a list of tasks for finding time zone names.
  config.time_zone = 'UTC'

  # The default locale is :en and all translations from config/locales/*.rb,yml are auto loaded.
  # config.i18n.load_path += Dir[Rails.root.join('my', 'locales', '*.{rb,yml}')]
  # config.i18n.default_locale = :de
end


#
# Metasploit Initialization
#

require 'rex'
require 'msf/ui'
require 'msf/base'

$msfweb      = Msf::Ui::Web::Driver.new({'LogLevel' => 5})
$msframework = $msfweb.framework

if ($browser_start)
	Thread.new do
		
		select(nil, nil, nil, 0.5)
		
		case RUBY_PLATFORM
		when /mswin32|cygwin/
			system("cmd.exe /c start #{$browser_url}")
		when /darwin/
			system("open #{$browser_url}")
		else
			system("firefox #{$browser_url} &")
		end
	end
end
