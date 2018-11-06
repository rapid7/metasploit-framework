unless File.const_defined? :NULL
  module File::Constants
    platform = RUBY_PLATFORM
    platform = RbConfig::CONFIG['host_os'] if platform == 'java'
    NULL =  case platform
            when /mswin|mingw/i
              'NUL'
            when /amiga/i
              'NIL:'
            when /openvms/i
              'NL:'
            else
              '/dev/null'
            end
  end
end
