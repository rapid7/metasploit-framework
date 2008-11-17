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

        Gtk::AboutDialog.set_email_hook do |about, link|
          Rex::Compat.open_email(link)
        end

        Gtk::AboutDialog.set_url_hook do |about, link|
          Rex::Compat.open_browser(link)
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
          self.logo = driver.get_icon('splash.xpm')
          self.website = Gtk2::WEBSITE_URL
          self.license = File.read(File.join(Msf::Config.install_root, 'README'))
          self.transient_for = parent
          self.signal_connect('response') { self.destroy }
        end
        
      end

    end
  end
end