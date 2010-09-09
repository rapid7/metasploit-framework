backend = case ENV['METASM_GUI']
when 'gtk'; 'gtk'
when 'qt'; 'qt'
when 'win32'; 'win32'
else
	puts "Unsupported METASM_GUI #{ENV['METASM_GUI'].inspect}" if $VERBOSE and ENV['METASM_GUI']
	if RUBY_PLATFORM =~ /i.86-(mswin32|mingw32|cygwin)/i
		'win32'
	else
	begin
		require 'gtk2'
		'gtk'
	rescue LoadError
		#begin
		#	require 'Qt4'
		#	'qt'
		#rescue LoadError
			raise LoadError, 'No GUI ruby binding installed - please install libgtk2-ruby'
		#end
	end
	end
end
require "metasm/gui/#{backend}"
