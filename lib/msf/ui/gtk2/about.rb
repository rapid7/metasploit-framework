module Msf
module Ui
module Gtk2

class MyAbout
    include Msf::Ui::Gtk2::MyControls
    
    def initialize
	@about = Gtk::AboutDialog.new
	@about.set_name('MSFGtk2')
	@about.set_website('http://www.metasploit.org')
	@about.set_authors(['Fabrice MOURRON" Fab', 'Metasploit LLC'])
	@about.set_license(File.read(File.join(Msf::Config.install_root, 'documentation', 'LICENSE')))
	#@about.set_wrap_license('True')
	@about.set_logo(driver.get_icon('msfwx.xpm'))
	@about.set_version("\nMetasploit Framework v#{Msf::Framework::Version}")
	@about.run
	@about.destroy
    end
end

end
end
end