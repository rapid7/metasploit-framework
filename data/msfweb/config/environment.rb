#
# Force the application into production mode
#
ENV['RAILS_ENV'] = 'production'

# Specifies gem version of Rails to use when vendor/rails is not present
RAILS_GEM_VERSION = '2.3.2' unless defined? RAILS_GEM_VERSION


#
# Find ourselves
#
msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

#
# Initialize the Rex library
# 
$:.unshift(File.join(File.dirname(msfbase), '..', '..', '..','lib'))
require 'rex'

#
# Create a secret key for this system
#
kfile = File.join(File.join(File.dirname(msfbase), '..', 'log', 'session.key'))
if(not File.exists?(kfile))
	kdata = ::Rex::Text.rand_text_alphanumeric(30)

	# Create the new session key file
	fd = File.new(kfile, 'w')

	# Make this file mode 0640
	File.chmod(0640, kfile)

	# Write it and close
	fd.write(kdata)
	fd.close
end
skey = File.read(kfile)

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
	config.time_zone = 'UTC'
	config.frameworks -= [ :active_record, :active_resource, :action_mailer ]
	config.action_controller.session = 
		{ 
			:session_key => "_msfweb_session",
			:secret      => skey
		}
end


#
# Metasploit Initialization
#

$stderr.puts "[*] Initializing the Metasploit Framework..."
require 'msf/ui'
require 'msf/base'

$msfweb      = Msf::Ui::Web::Driver.new({'LogLevel' => 5})
$msframework = $msfweb.framework

$stderr.puts "[*] Initialized the Metasploit Framework"

if ($browser_start)
	$stderr.puts "[*] Launching the default web browser..."
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
