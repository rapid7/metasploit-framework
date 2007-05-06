module Msf
module Ui
module Gtk2


##
# This class perform a wizard
##
class Assistant < Gtk::Window
	
	include Msf::Ui::Gtk2::MyControls
	
	attr_accessor :vbox, :hbox, :main, :page, :bbox, :vbox_left, :vbox_label
	
	def initialize(title)
		super
		self.resizable = false
		self.set_default_size(600, 400)
		self.title = title
		
		@page = "intro"
		
		# VBox
		@vbox = Gtk::VBox.new(false, 10)
		self.add(@vbox)
		
		# MSF Banner
		@vbox.pack_start(create_banner(), false, false, 0)
		
		# HBox
		@hbox = Gtk::HBox.new(false, 10)
		@vbox.pack_start(@hbox, true, false, 0)
		
		# Left frame
		@vbox_left = Gtk::VBox.new(false, 5)
		@hbox.pack_start(@vbox_left, false, false, 10)
		@vbox_left.pack_start(create_frame(), false, false, 10)
		@vbox_left.pack_start(create_save(), false, false, 5)
		
		# Main frame
		@main = Gtk::VBox.new(false, 5)
		@hbox.pack_start(@main, true, true, 5)
		
		# Separator
		separator = Gtk::HSeparator.new
		@vbox.pack_start(separator, false, false, 0)

		# Buttons
		@bbox = Gtk::HButtonBox.new
		@bbox.set_border_width(5)
		@bbox.layout_style = Gtk::ButtonBox::END
		@bbox.set_spacing(10)
		create_buttons()
		@vbox.pack_end(@bbox, false, false, 0)	
		
		# Signals
		self.signal_connect('destroy') do
			self.destroy
		end
	end
	
	#
	# Display the left frame
	#
	def populate_frame(array)
		array.each do |item|
			@vbox_label.pack_start(item, false, false, 0)
		end
	end
	
	#
	# TODO: Add this fun feature
	#
	def create_save
		save_button = Gtk::Button.new(Gtk::Stock::SAVE)
		$gtk2driver.tips.set_tip(save_button, "Save your configuration", nil)
		save_button.signal_connect('clicked') do
			MsfDialog::Error.new(self, "Not available")
		end
		return save_button
	end
	
	#
	# next_page signal function
	#
	def next_page
		raise NotImplementedError, "Subclass must implement next_page()"
	end

	#
	# back_page signal function
	#
	def back_page
		raise NotImplementedError, "Subclass must implement back_page()"
	end

	#
	# apply signal function
	#
	def apply
		raise NotImplementedError, "Subclass must implement apply()"
	end
	
	#
	# Create Label, the foreground color was determining by the state
	# state = (true or false)
	#
	def create_label(state, text)
		label = Gtk::Label.new
		label.set_alignment(0, 0)
		if state
			label.set_markup("<span foreground=\"black\"><b>#{text}</b></span>")
		else
			label.set_markup("<span foreground=\"#C0C0C0\">#{text}</span>")
		end
		return label
	end
	
	#
	# Create dynamics buttons
	#
	def create_buttons
		@button_cancel = Gtk::Button.new(Gtk::Stock::CANCEL)
		@button_cancel.signal_connect('clicked') do
			self.destroy
		end
		
		@button_back = Gtk::Button.new(Gtk::Stock::GO_BACK)
		@button_back.signal_connect('clicked') do
			back_page()
		end

		@button_apply = Gtk::Button.new(Gtk::Stock::APPLY)
		@button_apply.signal_connect('clicked') do
			apply()
			self.destroy
		end
		
		@button_forward = Gtk::Button.new(Gtk::Stock::GO_FORWARD)
		@button_forward.signal_connect('clicked') do
			next_page
		end
		
		# Display buttons
		display()
	end
	
	#
	# Init and refresh the backend buttons
	# Refresh the main view
	#
	def display
		
		# Remove all buttons on the bbox
		@bbox.each do |widget|
			@bbox.remove(widget)
		end
		
		# Remove all widgets and the main view
		@main.each do |widget|
			@main.remove(widget)
		end
		
		# Add buttons
		@bbox.add(@button_cancel)
		if (not @page == "intro")
			@bbox.add(@button_back)
		end
		
		if (@page == "end")
			@bbox.add(@button_apply)
		else
			@bbox.add(@button_forward)
		end
		
		@bbox.show_all
	end
	
	#
	# Refresh the left frame
	#
	def refresh_label(hist, actual , nex)
		if not (hist == nil)
			hist.each do |label|
				label.set_markup("<span foreground=\"white\"><i>#{label.text}</i></span>")
			end
		end
		
		actual.each do |label|
			label.set_markup("<span foreground=\"black\"><b>#{label.text}</b></span>")
		end
		
		if not (nex == nil)
			nex.each do |label|
				label.set_markup("<span foreground=\"#C0C0C0\"><b>#{label.text}</b></span>")
			end
		end
	end
	
	#########
	private #
	#########
	
	#
	# Create and return a DrawingArea object
	#
	def create_banner
		
		#
		# Not use for this moment ...
		#
		# da = Gtk::DrawingArea.new
		# da.set_size_request(600, 60)
		# 
		# # Signal
		# da.signal_connect('expose-event') do |widget, event|
			# cr = widget.window.create_cairo_context
			# cr.scale(*widget.window.size)
			# cr.set_line_width(0.04)
			# 
			# cr.new_path
			# image = Cairo::ImageSurface.from_png(driver.get_image("banner_assistant.png"))
			# cr.scale(1.0 / image.width, 1.0 / image.height)
			# cr.set_source(image, 0, 0)
			# 
			# cr.paint
		# end
		
		da = Gtk::Image.new(driver.get_image("banner_assistant.png"))
		
		return da
	end
	
	#
	# Create and return the left frame
	#
	def create_frame
		frame_label = Gtk::Frame.new
		frame_label.set_shadow_type(Gtk::SHADOW_ETCHED_IN)
		@vbox_label = Gtk::VBox.new(false, 20)
		frame_label.add(@vbox_label)
		
		return frame_label
	end
end

end
end
end
