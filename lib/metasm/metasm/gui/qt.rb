#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'Qt4'

module Metasm
module Gui

module Protect
	@@lasterror = Time.now
	def protect
		yield
	rescue Object
		puts $!.message, $!.backtrace	# also dump on stdout, for c/c
		delay = Time.now-@@lasterror
		sleep 1-delay if delay < 1	# msgbox flood protection
		@@lasterror = Time.now
		messagebox([$!.message, $!.backtrace].join("\n"), $!.class.name)
	end
end

module Msgbox
	include Protect

	# shows a message box (non-modal)
	# args: message, title/optionhash
	def messagebox(text, opts={})
		opts = {:title => opts} if opts.kind_of? String
		mbox = Qt::MessageBox.new#(self)
		mbox.text = text
		mbox.window_title = opts[:title] if opts[:title]
		mbox.window_modality = Qt::NonModal
		mbox.show
		mbox
	end

	# asks for user input, yields the result (unless 'cancel' clicked)
	# args: prompt, :text => default text, :title => title
	def inputbox(prompt, opts={})
		ibox = Qt::InputDialog.new#(self)
		ibox.label_text = prompt
		ibox.window_title = opts[:title] if opts[:title]
		ibox.text_value = opts[:text] if opts[:text]
		connect(ibox, SIGNAL('TextValueSelected(v)')) { |v| protect { yield v } }
		ibox.show
		ibox
	end

	@@dialogfilefolder = nil

	# asks to chose a file to open, yields filename
	# args: title, :path => path
	def openfile(title, opts={})
		f = Qt::FileDialog.get_open_file_name(nil, title, @@dialogfilefolder)
		if f and f != ''
			@@dialogfilefolder = File.dirname(f)
			protect { yield f }
		end
		f	# useless, dialog is modal
	end

	# same as openfile, but for writing a (new) file
	def savefile(title, opts={})
		f = Qt::FileDialog.get_save_file_name(nil, title, @@dialogfilefolder)
		if f and f != ''
			@@dialogfilefolder = File.dirname(f)
			protect { yield f }
		end
		f	# useless, dialog is modal
	end

	# shows a window with a list of items
	# the list is an array of arrays, displayed as String
	# the first array is the column names
	# each item clicked yields the block with the selected iterator, double-click also close the popup
	# args: title, [[col0 title, col1 title...], [col0 val0, col1 val0...], [val1], [val2]...]
	def listwindow(title, list, h={})
		l = Qt::TreeWidget.new#(self)
		l.window_title = title

		cols = list.shift
		#l.column_count = cols.length
		l.header_labels = cols
		list.each { |e|
			i = Qt::TreeWidgetItem.new
			e.length.times { |idx| i.set_text(idx, e[idx].to_s) }
			l.add_top_level_item i
		}

		connect(l, SIGNAL('itemActivated(QTreeWidgetItem*,int)')) { |item, col|
			next if not item.is_selected
			next if not idx = l.index_of_top_level_item(item)
			protect { yield(list[idx].map { |e| e.to_s }) } #if iter = treeview.selection.selected
		}
		connect(l, SIGNAL('itemDoubleClicked(QTreeWidgetItem*,int)')) { l.close }
		l.resize(cols.length*120, 400)
		l.show if not h[:noshow]
		l
	end
end

# a widget that holds many other widgets, and displays only one of them at a time
class ContainerChoiceWidget < Qt::StackedWidget
	include Msgbox

	attr_accessor :views, :view_indexes
	def initialize(*a)
		super()
		@views = {}
		@view_indexes = []

		initialize_widget(*a)
		initialize_visible if respond_to? :initialize_visible
	end

	def view(i)
		@views[i]
	end

	def showview(i)
		set_current_index @view_indexes.index(i)
	end

	def addview(name, w)
		@view_indexes << name
		@views[name] = w
		add_widget w
	end

	def curview
		@views[curview_index]
	end

	def curview_index
		@view_indexes[current_index]
	end
end

class ContainerVBoxWidget < Qt::VBoxLayout
	def initialize(*a)
		super()

		signal_connect('realize') { initialize_visible } if respond_to? :initialize_visible

		signal_connect('size_request') { |w, alloc| resize(*alloc) } if respond_to? :resize

		self.spacing = 2

		initialize_widget(*a)
	end
end

class DrawableWidget < Qt::Widget
	include Msgbox

	attr_accessor :parent_widget, :caret_x, :caret_y, :hl_word
	# this hash is used to determine the colors of the GUI elements (background, caret, ...)
	# modifications to it are only useful before the widget is first rendered (IE before GUI.main)
	attr_accessor :default_color_association

	# keypress event keyval traduction table
	# RHA no way to enumerate all Key_* constants, they are handled in Qt.const_missing
	Keyboard_trad = %w[
Escape Tab Backtab Backspace Return Enter Insert Delete Pause Print SysReq Clear Home End Left Up Right
Down PageUp PageDown Shift Control Meta Alt AltGr CapsLock NumLock ScrollLock
F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23 F24 F25 F26 F27 F28 F29 F30 F31 F32 F33 F34 F35 Super_L Super_R
Menu Hyper_L Hyper_R Help Direction_L Direction_R nobreakspace exclamdown cent sterling currency yen brokenbar section diaeresis copyright
ordfeminine guillemotleft notsign hyphen registered macron degree plusminus twosuperior threesuperior acute mu paragraph periodcentered cedilla onesuperior
masculine guillemotright onequarter onehalf threequarters questiondown Agrave Aacute Acircumflex Atilde Adiaeresis Aring AE Ccedilla Egrave Eacute
Ecircumflex Ediaeresis Igrave Iacute Icircumflex Idiaeresis ETH Ntilde Ograve Oacute Ocircumflex Otilde Odiaeresis multiply Ooblique Ugrave
Uacute Ucircumflex Udiaeresis Yacute THORN ssharp division ydiaeresis Multi_key Codeinput SingleCandidate MultipleCandidate PreviousCandidate Mode_switch Kanji Muhenkan
Henkan Romaji Hiragana Katakana Hiragana_Katakana Zenkaku Hankaku Zenkaku_Hankaku Touroku Massyo Kana_Lock Kana_Shift Eisu_Shift Eisu_toggle Hangul Hangul_Start
Hangul_End Hangul_Hanja Hangul_Jamo Hangul_Romaja Hangul_Jeonja Hangul_Banja Hangul_PreHanja Hangul_PostHanja Hangul_Special Dead_Grave Dead_Acute Dead_Circumflex Dead_Tilde Dead_Macron Dead_Breve Dead_Abovedot
Dead_Diaeresis Dead_Abovering Dead_Doubleacute Dead_Caron Dead_Cedilla Dead_Ogonek Dead_Iota Dead_Voiced_Sound Dead_Semivoiced_Sound Dead_Belowdot Dead_Hook Dead_Horn Back Forward Stop Refresh
VolumeDown VolumeMute VolumeUp BassBoost BassUp BassDown TrebleUp TrebleDown MediaPlay MediaStop MediaPrevious MediaNext MediaRecord HomePage Favorites Search
Standby OpenUrl LaunchMail LaunchMedia Launch0 Launch1 Launch2 Launch3 Launch4 Launch5 Launch6 Launch7 Launch8 Launch9 LaunchA LaunchB
LaunchC LaunchD LaunchE LaunchF MediaLast unknown Call Context1 Context2 Context3 Context4 Flip Hangup No Select Yes
Execute Printer Play Sleep Zoom Cancel
	].inject({}) { |h, cst|
		v = Qt.const_get("Key_#{cst}").to_i	# AONETUHANOTEUHATNOHEU Qt::Enum != Fixnum
		key = cst.downcase.to_sym
		key = { :pageup => :pgup, :pagedown => :pgdown, :escape => :esc, :return => :enter }.fetch(key, key)
		h.update v => key
	}

	def initialize(*a)
		@parent_widget = nil

		@caret_x = @caret_y = 0		# text cursor position
		@oldcaret_x = @oldcaret_y = 1
		@hl_word = nil

		#@layout = Pango::Layout.new Gdk::Pango.context	# text rendering

		@color = {}
		@default_color_association = {:background => :palegrey}

		if a.last.kind_of? Qt::Widget
			super(a.last)
		else
			super()
		end

		{ :white => 'fff', :palegrey => 'ddd', :black => '000', :grey => '444',
		  :red => 'f00', :darkred => '800', :palered => 'fcc',
		  :green => '0f0', :darkgreen => '080', :palegreen => 'cfc',
		  :blue => '00f', :darkblue => '008', :paleblue => 'ccf',
		  :yellow => 'ff0', :darkyellow => '440', :paleyellow => 'ffc',
		}.each { |tag, val| @color[tag] = color(val) }

		initialize_widget(*a)
		set_auto_fill_background true
		set_color_association @default_color_association
		set_focus_policy Qt::StrongFocus

		initialize_visible if respond_to? :initialize_visible

		set_font 'courier 10'
	end

	def keyPressEvent(key)
		val = key.key >= 128 ? Keyboard_trad[key.key] : key.text[0].ord	# must use text[0] to differenciate downcase/upcase
		if key.modifiers.to_i & Qt::ControlModifier.to_i > 0	# AONETHUAAAAAAAAAAAAAAA
			protect { keypress_ctrl(val) } if respond_to? :keypress_ctrl
		else
			protect { keypress(val) } if respond_to? :keypress
		end
	end

	def mousePressEvent(ev)
		if ev.modifiers.to_i & Qt::ControlModifier.to_i > 0
			protect { click_ctrl(ev.x, ev.y) } if respond_to? :click_ctrl
		else
			if ev.button == Qt::LeftButton
				protect { click(ev.x, ev.y) }
			elsif ev.button == Qt::RightButton
				protect { rightclick(ev.x, ev.y) } if respond_to? :rightclick
			end
		end
	end

	def mouseDoubleClickEvent(ev)
		protect { doubleclick(ev.x, ev.y) } if respond_to? :doubleclick
	end

	def mouseReleaseEvent(ev)
		if ev.button == Qt::LeftButton
			protect { mouserelease(ev.x, ev.y) } if respond_to? :mouserelease
		end
	end

	def mouseMoveEvent(ev)
		if ev.modifiers.to_i & Qt::ControlModifier.to_i > 0
			protect { mousemove_ctrl(ev.x, ev.y) } if respond_to? :mousemove_ctrl
		else
			protect { mousemove(ev.x, ev.y) } if respond_to? :mousemove
		end
	end

	def wheelEvent(ev)
		dir = ev.delta > 0 ? :up : :down
		if ev.modifiers.to_i & Qt::ControlModifier.to_i > 0
			protect { mouse_wheel_ctrl(dir, ev.x, ev.y) } if respond_to? :mouse_wheel_ctrl
		else
			protect { mouse_wheel(dir, ev.x, ev.y) } if respond_to? :mouse_wheel
		end
	end

	def resizeEvent(ev)
		protect { resized(ev.size.width, ev.size.height) } if respond_to? :resized
	end

	def grab_focus; set_focus end

	def paintEvent(*a)
		@painter = Qt::Painter.new(self)
		protect { paint }
		@painter.end
		@painter = nil
	end

	def paint
	end

	def gui_update
		redraw
	end

	# create a color from a 'rgb' description
	def color(val)
		@color[val] ||= Qt::Color.new(*val.unpack('CCC').map { |c| (c.chr*2).hex })
	end

	def set_caret_from_click(x, y)
		@caret_x = (x-1).to_i / @font_width
		@caret_y = y.to_i / @font_height
		update_caret
	end

	# change the font of the widget
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		descr, sz = descr.split
		super(Qt::Font.new(descr, sz.to_i))
		@font_width = font_metrics.width('x')
		@font_height = font_metrics.line_spacing
		@font_descent = font_metrics.descent
		gui_update
	end

	# change the color association
	# arg is a hash function symbol => color symbol
	# color must be allocated
	# check #initialize/sig('realize') for initial function/color list
	def set_color_association(hash)
		hash.each { |k, v| @color[k] = color(v) }
		#set_background_role Qt::Palette::Window(color(:background))
		palette.set_color(Qt::Palette::Window, color(:background))
		gui_update
	end

	# update @hl_word from a line & offset, return nil if unchanged
	def update_hl_word(line, offset)
		return if not line
		word = line[0...offset].to_s[/\w*$/] << line[offset..-1].to_s[/^\w*/]
		word = nil if word == ''
		@hl_word = word if @hl_word != word
	end

	# invalidate the whole widget area
	def redraw
		invalidate(0, 0, 1000000, 1000000)
	end

	def invalidate_caret(cx, cy, x=0, y=0)
		invalidate(x + cx*@font_width, y + cy*@font_height, 2, @font_height)
	end

	def invalidate(x, y, w, h)
		update x, y, w, h
	end

	def resized(w, h)
		redraw
	end

	def keypress(key)
	end

	def keypress_ctrl(key)
	end

	def draw_color(col)
		@col = color(col)
		@painter.set_brush Qt::Brush.new(@col)
		@painter.set_pen Qt::Pen.new(@col)
	end

	def draw_rectangle(x, y, w, h)
		@painter.fill_rect(x, y, w, h, @col)
	end

	def draw_rectangle_color(col, x, y, w, h)
		draw_color(col)
		draw_rectangle(x, y, w, h)
	end

	def draw_line(x, y, ex, ey)
		@painter.draw_line(x, y, ex, ey)
	end

	def draw_line_color(col, x, y, ex, ey)
		draw_color(col)
		draw_line(x, y, ex, ey)
	end

	def draw_string(x, y, str)
		@painter.draw_text(x, y-@font_descent, str)
	end

	def draw_string_color(col, x, y, str)
		draw_color(col)
		draw_string(x, y, str)
	end
end

class Window < Qt::MainWindow
	include Msgbox

	attr_accessor :menu
	def initialize(*a)
		super()

		#connect(self, SIGNAL(:destroy)) { destroy_window }

		@menu = menu_bar

		screen = Qt::Application.desktop
		resize screen.width*3/4, screen.height*3/4

		initialize_window(*a)
		build_menu

		show
	end

	def build_menu
	end

	def destroy_window
	end

	def widget=(w)
		set_central_widget w
	end

	def title=(t); set_window_title(t) end
	def title; window_title end

	def new_menu
		Qt::Menu.new
	end

	def addsubmenu(menu, *args)
		accel = args.grep(/^\^?(\w|<\w+>)$/).first
		args.delete accel if accel
		check = args.delete :check
		submenu = args.grep(Qt::Menu).first
		args.delete submenu if submenu
		if label = args.shift
			label = label.capitalize if label == label.upcase	# TODO icon on OPEN/CLOSE etc
			label = label.gsub('_', '&')
		end

		if submenu
			submenu.title = label
			menu.add_menu submenu
			return
		end

		if check
			# TODO
			#item = Gtk::CheckMenuItem.new(label)
			#item.active = args.shift
			item = Qt::Action.new(label, self)
			menu.add_action item
		elsif label
			item = Qt::Action.new(label, self)
			menu.add_action item
		else
			menu.add_separator
		end
		item.setShortcut accel.sub('^', 'Ctrl+')

		connect(item, SIGNAL(:triggered)) { protect { yield(item) } } if block_given?

		item
	end
end

@app = Qt::Application.new ARGV

# start the GUI main loop
def self.main
	@app.exec
end

# ends the GUI main loop
def self.main_quit
	@app.quit	# XXX segfault..
end

# register a proc to be run whenever the gui loop is idle
# if the proc returns nil/false, delete it
def self.idle_add
	t = Qt::Timer.new
	t.connect(t, SIGNAL(:timeout)) { if not yield ; t.stop ; t = nil end }
	t.start
end

# run a single iteration of the main_loop
# e.g. call this from time to time when doing heavy computation, to keep the UI somewhat responsive
def self.main_iter
	Qt::Application.process_events
end

end
end

require 'metasm/gui/dasm_main'
require 'metasm/gui/debug'

