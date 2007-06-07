module Msf
  module Ui
    module Gtk2

      TITLE = 'msfgui'
      DESCRIPTION = 'A Gtk2 interface for Metasploit framework.'
      COPYRIGHT = 'Copyright (C) 2006-2007 Metasploit LLC'
      AUTHORS = [
        'Fabrice MOURRON <fab@metasploit.com>',
        'HD Moore <hdm@metasploit.com>'
      ]
      DOCUMENTERS = [
        ''
      ]
      ARTISTS = [
        'Fabrice MOURRON <fab@metasploit.com>',
        'Anonymous <anonymous@metasploit.com'
      ]
      LIST = 'framework-subscribe@metasploit.com'
      BUGREPORT_URL = 'http://metasploit.com/dev/trac/report/9'
      WEBSITE_URL = 'http://www.metasploit.com'
      VERSION = "based on MSF v#{Msf::Framework::Version}"

      #
      # The log source used by the gtk2 service.
      #
      LogSource = "msfgui"

    end
  end
end

require 'msf/ui/gtk2/driver'
