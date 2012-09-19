##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##


module Erubis

  ##
  ## helper for xml
  ##
  module XmlHelper

    module_function

    ESCAPE_TABLE = {
      '&' => '&amp;',
      '<' => '&lt;',
      '>' => '&gt;',
      '"' => '&quot;',
      "'" => '&#039;',
    }

    def escape_xml(value)
      value.to_s.gsub(/[&<>"]/) { |s| ESCAPE_TABLE[s] }   # or /[&<>"']/
      #value.to_s.gsub(/[&<>"]/) { ESCAPE_TABLE[$&] }
    end

    def escape_xml2(value)
      return value.to_s.gsub(/\&/,'&amp;').gsub(/</,'&lt;').gsub(/>/,'&gt;').gsub(/"/,'&quot;')
    end

    alias h escape_xml
    alias html_escape escape_xml

    def url_encode(str)
      return str.gsub(/[^-_.a-zA-Z0-9]+/) { |s|
        s.unpack('C*').collect { |i| "%%%02X" % i }.join
      }
    end

    alias u url_encode

  end


end
