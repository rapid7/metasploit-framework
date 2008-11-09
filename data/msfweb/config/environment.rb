#
# Force the application into production mode
#
ENV['RAILS_ENV'] = 'production'


# Specifies gem version of Rails to use when vendor/rails is not present
RAILS_GEM_VERSION = '1.2.3' unless defined? RAILS_GEM_VERSION

# Bootstrap the Rails environment, frameworks, and default configuration
require File.join(File.dirname(__FILE__), 'boot')

#
# New versions of Rails force the KCODE to unicode. This breaks
# binary string generation used by Metasploit for shellcode,
# text generation, and encoding. We override the initialize_encoding
# method and force KCODE to be 'NONE'
#
class Rails::Initializer
	def initialize_encoding
		$KCODE = 'NONE'
	end
end

# Initialize Rails
Rails::Initializer.run do |config|
	config.log_level = :warn
	config.active_record.allow_concurrency = true
	config.frameworks -= [ :active_record ]
	config.action_controller.session = 
		{ 
			:session_key => "_msfweb_session",
			:secret      => ::Rex::Text.rand_text_alphanumeric(30)
		}	
end


msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', '..', '..', 'lib'))



# Monkey patch the webrick vulnerability
if(Object.const_defined?(:WEBrick))
	load(File.join(File.dirname(msfbase), "..", "patches", "filehandler.rb"))
end

require 'rex'
require 'msf/ui'
require 'msf/base'

$msfweb      = Msf::Ui::Web::Driver.new({'LogLevel' => 5})
$msframework = $msfweb.framework

if ($browser_start)
	Thread.new do
		
		select(nil, nil, nil, 0.5)
		
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
