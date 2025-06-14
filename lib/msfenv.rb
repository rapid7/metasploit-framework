# Use bundler to load dependencies
#

# Enable legacy providers such as blowfish-cbc, cast128-cbc, arcfour, etc
$stderr.puts "Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions." unless ENV['OPENSSL_CONF'].nil?
ENV['OPENSSL_CONF'] = File.expand_path(
  File.join(File.dirname(__FILE__), '..', 'config', 'openssl.conf')
)

if ENV['KRB5CCNAME']
  $stderr.puts 'Warning: KRB5CCNAME environment variable not supported - unsetting'
  ENV['KRB5CCNAME'] = nil
end

# Override the normal rails default, so that msfconsole will come up in production mode instead of development mode
# unless the `--environment` flag is passed.
ENV['RAILS_ENV'] ||= 'production'

require 'pathname'
root = Pathname.new(__FILE__).expand_path.parent.parent
config = root.join('config')
require config.join('boot')

# Requiring environment will define the Metasploit::Framework::Application as the one and only Rails::Application in
# this process and cause an error if a Rails.application is already defined, such as when loading msfenv through
# msfconsole in Metasploit Pro.
unless defined?(Rails) && !Rails.application.nil?
  require config.join('environment')
end
require 'msf_autoload'

# Disable the enhanced error messages introduced as part of Ruby 3.1, as some error messages are directly shown to users,
# and the default ErrorHighlight formatter displays unneeded Ruby code to the user
# https://github.com/ruby/error_highlight/tree/f3626b9032bd1024d058984329accb757687cee4#custom-formatter
if defined?(::ErrorHighlight)
  noop_error_formatter = Object.new
  def noop_error_formatter.message_for(_spot)
    ''
  end
  ::ErrorHighlight.formatter = noop_error_formatter
end

MsfAutoload.instance

def _warn_deprecation_message(method)
  stack_size = 3
  warning_message = "[DEPRECATION] The global method #{method.inspect} is deprecated, please raise a Github issue with this output. Called from: #{caller(1, stack_size).to_a}"
  warn(warning_message)
  # Additionally write to ~/.msf4/logs/framework.log - as this gets attached to Github issues etc
  elog(warning_message)
end

# @deprecated In most scenarios you should delegate to either a framework module object, or Rex::Ui::Text::DispatcherShell etc
def print_line(msg)
  _warn_deprecation_message __method__
  $stdout.puts(msg)
end

# @deprecated In most scenarios you should delegate to either a framework module object, or Rex::Ui::Text::DispatcherShell etc
def print_warning(msg)
  _warn_deprecation_message __method__
  $stderr.puts(msg)
end

# @deprecated In most scenarios you should delegate to either a framework module object, or Rex::Ui::Text::DispatcherShell etc
def print_good(msg)
  _warn_deprecation_message __method__
  $stdout.puts(msg)
end

# @deprecated In most scenarios you should delegate to either a framework module object, or Rex::Ui::Text::DispatcherShell etc
def print_error(msg, exception = nil)
  _warn_deprecation_message __method__

  unless exception.nil?
    msg += "\n    Call Stack:"
    exception.backtrace.each {|line|
      msg += "\n"
      msg += "\t #{line}"
    }
  end

  $stderr.puts(msg)
end
