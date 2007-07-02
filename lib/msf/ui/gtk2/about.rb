module Msf
  module Ui
    module Gtk2

      ###
      #
      # This class provides the about button
      #
      ###
      class MyAbout < Gtk::AboutDialog

        include Msf::Ui::Gtk2::MyControls

        # TODO
        Gtk::AboutDialog.set_email_hook do |about, link|
          puts "Mail to #{link}"
        end
        
        # TODO
        Gtk::AboutDialog.set_url_hook do |about, link|
          puts "Launch a browser to url #{link}"
        end

        def initialize(parent)
          super()
          self.name = Gtk2::TITLE
          self.version = Gtk2::VERSION
          self.copyright = Gtk2::COPYRIGHT
          self.comments = Gtk2::DESCRIPTION
          self.authors = Gtk2::AUTHORS
          self.documenters = Gtk2::DOCUMENTERS
          self.artists = Gtk2::ARTISTS
          self.logo = driver.get_icon('msfwx.xpm')
          self.website = Gtk2::WEBSITE_URL
          self.license = File.read(File.join(Msf::Config.install_root, 'documentation', 'LICENSE'))
          self.transient_for = parent
          self.signal_connect('response') { self.destroy }
        end
        
      end

    end
  end
end
