#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this is a little script to navigate in a disassembler dump
#

# copypasted from lindebug.rb
module Ansi
	CursHome = "\e[H".freeze
	ClearLineAfter  = "\e[0K"
	ClearLineBefore = "\e[1K"
	ClearLine = "\e[2K"
	ClearScreen = "\e[2J"
	def self.set_cursor_pos(y=1,x=1) "\e[#{y};#{x}H" end
	Reset = "\e[m"
	Colors = [:black, :red, :green, :yellow, :blue, :magenta, :cyan, :white, :aoeu, :reset]
	def self.color(*args)
		fg = true
		"\e[" << args.map { |a|
			case a
			when :bold; 2
			when :negative; 7
			when :normal; 22
			when :positive; 27
			else
				if col = Colors.index(a)
					add = (fg ? 30 : 40)
					fg = false
					col+add
				end
			end
		}.compact.join(';') << 'm'
	end
	def self.hline(len) "\e(0"<<'q'*len<<"\e(B" end

	TIOCGWINSZ = 0x5413
	TCGETS = 0x5401
	TCSETS = 0x5402
	CANON = 2
	ECHO  = 8
	def self.get_terminal_size
		s = ''.ljust(8)
		$stdin.ioctl(TIOCGWINSZ, s) >= 0 ? s.unpack('SS') : [80, 25]
	end
	def self.set_term_canon(bool)
		tty = ''.ljust(256)
		$stdin.ioctl(TCGETS, tty)
		if bool
			tty[12] &= ~(ECHO|CANON)
		else
			tty[12] |= ECHO|CANON
		end
		$stdin.ioctl(TCSETS, tty)
	end

	ESC_SEQ = {'A' => :up, 'B' => :down, 'C' => :right, 'D' => :left,
		'1~' => :home, '2~' => :inser, '3~' => :suppr, '4~' => :end,
		'5~' => :pgup, '6~' => :pgdown,
		'P' => :f1, 'Q' => :f2, 'R' => :f3, 'S' => :f4,
		'15~' => :f5, '17~' => :f6, '18~' => :f7, '19~' => :f8,
		'20~' => :f9, '21~' => :f10, '23~' => :f11, '24~' => :f12,
		'[A' => :f1, '[B' => :f2, '[C' => :f3, '[D' => :f4, '[E' => :f5,
		'H' => :home, 'F' => :end,
	}
	def self.getkey
		c = $stdin.getc
		return c if c != ?\e
		c = $stdin.getc
		if c != ?[ and c != ?O
			$stdin.ungetc c
			return ?\e
		end
		seq = ''
		loop do
			c = $stdin.getc
			seq << c
			case c; when ?a..?z, ?A..?Z, ?~; break end
		end
		ESC_SEQ[seq] || seq
	end
end

class Viewer
	attr_accessor :text, :pos, :x, :y

	Color = {
		:normal  => Ansi.color(:white, :black, :normal),
		:comment => Ansi.color(:blue),
		:label   => Ansi.color(:green),
		:hilight => Ansi.color(:yellow),
	}


	def initialize(text)
		text = File.read(text) if File.exist? text rescue nil
		@text = text.gsub("\t", " "*8).to_a.map { |l| l.chomp }
		@pos = @posh = 0
		@x = @y = 0
		@mode = :navig
		@searchtext = 'x'
		@posstack = []
		@h, @w = Ansi.get_terminal_size
		@h -= 2
		@w -= 1
		if y = @text.index('entrypoint:')
			view(0, y)
		end
	end

	def main_loop
		Ansi.set_term_canon(true)
		$stdout.write Ansi::ClearScreen
		begin
			loop do
				refresh if not s = IO.select([$stdin], nil, nil, 0)
				handle_key(Ansi.getkey)
			end
		ensure
			Ansi.set_term_canon(false)
			$stdout.write Ansi.set_cursor_pos(@h+2, 0) + Ansi::ClearLineAfter
		end
	end

	def refresh
		case @mode
		when :navig
			refresh_navig
		when :search
			refresh_search
		end
	end

	def refresh_navig
		str = ''
		#str << Ansi::ClearScreen
		str << Ansi.set_cursor_pos(0, 0)
		hl = readtext
		(0..@h).each { |h|
			l = @text[@pos+h] || ''
			str << outline(l, hl) << Ansi::ClearLineAfter << "\n"
		}
		str << Ansi.set_cursor_pos(@y+1, @x+1)
		$stdout.write str
	end

	def refresh_search
		$stdout.write '' << Ansi.set_cursor_pos(@h+2, 1) << '/' << @searchtext << Ansi::ClearLineAfter
	end

	def outline(l, hl=nil)
		l = l[@posh, @w] || ''
		hlr = /\b#{Regexp.escape(hl)}\b/i if hl
		case l
		when /^\/\//; Color[:comment] + l + Color[:normal]
		when /^\S+:$/; Color[:label] + l + Color[:normal]
		when /^(.*)(;.*)$/
			str = $1
			cmt = $2
			str.gsub!(hlr, Color[:hilight]+hl+Color[:normal]) if hl
			str + Color[:comment] + cmt + Color[:normal]
		else
			l = l.gsub(hlr, Color[:hilight]+hl+Color[:normal]) if hl
			l
		end
	end

	def search_prev
		return if @searchtext == ''
		y = @pos+@y-1
		loop do
			y = @text.length-1 if not @text[y] or y < 0
			if x = (@text[y] =~ /#@searchtext/i)
				view(x, y)
				return
			end
			y -= 1
			break if y == @pos+@y
		end
	end

	def search_next
		return if @searchtext == ''
		y = @pos+@y+1
		loop do
			y = 0 if not @text[y]
			if x = (@text[y] =~ /#@searchtext/i)
				view(x, y)
				return
			end
			break if y == @pos+@y or (y >= @text.length and not @text[@pos+@y])
			y += 1
		end
	end

	def view(x, y)
		@posh, @x = 0, x
		if @x > @w
			@posh = @w-@x
			@x = @w
		end
		if @pos+@h < y
			@y = @h/2-1
			@pos = y-@y
		elsif @pos > y
			@y = 1
			@pos = y-@y
		else
			@y = y-@pos
		end
	end

	def readtext
		return if not l = @text[@pos+@y]
		x = (l.rindex(/\W/, [@posh+@x-1, 0].max) || -1)+1
		t = l[x..-1][/^\w+/]
		t if t and @posh+@x < x+t.length
	end

	def handle_key(k)
		case @mode
		when :navig
			handle_key_navig(k)
		when :search
			handle_key_search(k)
		end
	end

	def handle_key_search(k)
		case k
		when ?\n; @mode = :navig ; @posstack << [@posh, @pos, @x, @y] ; search_next
		when 0x20..0x7e; @searchtext << k
		when :backspace, 0x7f; @searchtext.chop!
		end
	end

	def handle_key_navig(k)
		case k
		when :f1
			if not @posstack.empty?
				@posh, @pos, @x, @y = @posstack.pop
			end
		when ?\n
			return if not label = readtext
			return if label.empty? or not newy = @text.index(@text.find { |l| l[0, label.length] == label }) or newy == @pos+@y
			@posstack << [@posh, @pos, @x, @y]
			view(0, newy)
		when :up
			if @y > 0; @y -= 1
			elsif @pos > 0; @pos -= 1
			end
		when :down
			if @y < @h; @y += 1
			elsif @pos < text.length-@h; @pos += 1
			end
		when :home
			@x = @posh = 0
		when :end
			@x = @text[@pos+@y].length
			@posh, @x = @x-@w, @w if @x > @w
		when :left
			x = @text[@pos+@y].rindex(/\W\w/, [@posh+@x-2, 0].max)
			x = x ? x+1 : @posh+@x-1
			x = @posh+@x-3 if x < @posh+@x-3
			x = 0 if x < 0
			if x < @posh; @posh, @x = x, 0
			else @x = x-@posh
			end
			#if @x > 0; @x -= 1
			#elsif @posh > 0; @posh -= 1
			#end
		when :right
			x = @text[@pos+@y].index(/\W\w/, @posh+@x)
			x = x ? x+1 : @posh+@x+1
			x = @posh+@x+3 if x > @posh+@x+3
			if x > @posh+@w; @posh, @x = x-@w, @w
			else
				@x = x-@posh
				@posh, @x = @x-@w, @w if @x > @w
			end
			#if @x < @w; @x += 1
			#elsif @posh+@w < (@text[@pos, @h].map { |l| l.length }.max); @posh += 1
			#end
		when :pgdown
			if @y < @h/2; @y += @h/2
			elsif @pos < @text.length-3*@h/2; @pos += @h/2 ; @y = @h
			else @pos = [0, @text.length-@h].max ; @y = @h
			end
		when :pgup
			if @y > @h/2; @y -= @h/2
			elsif @pos > @h/2; @pos -= @h/2 ; @y = 0
			else @pos = @y = 0
			end
		when ?q; exit
		when ?o; @text.insert(@pos+@y+1, '')
		when ?O; @text.insert(@pos+@y, '') ; handle_key_navig(:down)
		when :suppr; @text.delete_at(@pos+@y) if @text[@pos+@y] == ''
		when ?D; @text.delete_at(@pos+@y)
		when ?/
			@mode = :search
			@searchtext = ''
		when ?*
			@searchtext = readtext || ''
			search_next
		when ?n; search_next
		when ?N; search_prev
		when :f5
			ARGV << '--reload'
			load $0
		end
	end
end

if $0 == __FILE__ and not ARGV.delete '--reload'
	Viewer.new(ARGF.read).main_loop
end
