module Msf
module Ui
module Wx
module MyControls

	#
	# Included class methods
	#

	# Get the global driver handle
	def driver
		$wxdriver
	end
	
	# Return the framework instance from the driver handler
	def framework
		driver.framework
	end

	def log(msg)
		if ($wxlogger)
			$wxlogger.append_text(msg + "\n")
		else
			$stderr.puts Time.now.to_s + " " + msg
		end
	end

	#
	# Controls
	# 

class MyModuleTree < ::Wx::TreeCtrl
    def initialize(parent, id,pos, size,style)
        super(parent, id, pos, size, style)
	end
end


class MyPanel < ::Wx::Panel

	attr_reader :m_note_modules, :m_note_console, :m_panel_exploits, :m_panel_payloads
	attr_reader :m_panel_encoders, :m_nops

    def initialize(frame,x,y,w,h)
        super( frame, -1, ::Wx::Point.new(x, y), ::Wx::Size.new(w, h) )
		
		set_auto_layout( TRUE )
		
		@m_size_panelv  = ::Wx::BoxSizer.new( ::Wx::VERTICAL )
		@m_size_panelh  = ::Wx::BoxSizer.new( ::Wx::HORIZONTAL )
		
		@m_note_modules = ::Wx::Notebook.new(self, NOTE_MODULES)
		@m_panel_info   = ::Wx::Panel.new( self )
		@m_note_console = ::Wx::Notebook.new(self, NOTE_CONSOLE)		

	
		# Create the module pages
		@m_panel_exploits = ::Wx::Panel.new(@m_note_modules)
		@m_panel_payloads = ::Wx::Panel.new(@m_note_modules)
		#@m_panel_encoders = ::Wx::Panel.new(@m_note_modules)
		#@m_panel_nops = ::Wx::Panel.new(@m_note_modules)
		
		@m_note_modules.add_page(@m_panel_exploits, 'Exploits')
		@m_note_modules.add_page(@m_panel_payloads, 'Payloads')	
	
		# Create the log/console pages
		@m_panel_log = ::Wx::Panel.new(@m_note_console)
		@m_panel_con = ::Wx::Panel.new(@m_note_console)
		
		@m_note_console.add_page(@m_panel_log, 'Logs')
		@m_note_console.add_page(@m_panel_con, 'Console')


		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel_log, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel_log, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel_log, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel_log, ::Wx::LAYOUT_WIDTH, 99 )
		
        @m_text_log = ::Wx::TextCtrl.new(
			@m_panel_log, -1,
			"",
			::Wx::Point.new(0, 250), 
			::Wx::Size.new(100, 50), 
			::Wx::TE_MULTILINE | ::Wx::TE_READONLY
		)
		@m_text_log.set_background_colour(::Wx::Colour.new("wheat"))
		@m_text_log.set_constraints(c)
		
		# Set the global logger instance
		$wxlogger = @m_text_log
		
		
		# Configure auto-layout
		[
			@m_panel_info,
			@m_panel_exploits,
			@m_panel_payloads,
			@m_panel_log,
			@m_panel_con
		].each { |panel| panel.set_auto_layout( TRUE ) }
			
		@m_size_panelv.add(@m_note_modules)
		@m_size_panelv.add(@m_panel_info)
		@m_size_panelv.add(@m_note_console)
			
		set_sizer(@m_size_panelv)
		
		evt_size {|event| on_size(event) }
			

       
	end
	
	
	def on_size(event)
		size = get_client_size()
		x = size.get_width
		y = size.get_height
		b = 4	
		
		if (@m_note_modules)
			@m_note_modules.set_dimensions( b, b, percent(33, x)-b, percent(80, y)-b )
		end
		
		if (@m_panel_info)
			@m_panel_info.set_dimensions( percent(33, x)+b, b, percent(67, x), percent(80, y))
		end
		
		if (@m_note_console)
			@m_note_console.set_dimensions( b, percent(80, y)+b, x-b, percent(20, y)-b )
			# @m_text_log.set_dimensions( b, percent(80, y)+b, x-b, percent(20, y)-b )
		end		
	end	
	
	
	def percent(mine, total)
		((mine.to_f / 100.0) * total).to_i
	end
	
end

	
end
end
end
end
