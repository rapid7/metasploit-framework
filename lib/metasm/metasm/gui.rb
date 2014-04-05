backend = ENV['METASM_GUI'] || (
  if RUBY_PLATFORM =~ /(i.86|x(86_)?64)-(mswin|mingw|cygwin)/i
    'win32'
  else
    begin
      require 'gtk2'
      'gtk'
    rescue LoadError
      raise LoadError, 'No GUI ruby binding installed - please install libgtk2-ruby'
    end
  end
)
require "metasm/gui/#{backend}"
