module Rake
  VERSION = '0.9.2.2'

  module Version # :nodoc: all
    MAJOR, MINOR, BUILD, PATCH = VERSION.split('.')
    NUMBERS = [ MAJOR, MINOR, BUILD, PATCH ]
  end
end
