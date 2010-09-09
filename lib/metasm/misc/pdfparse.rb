#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory
#
# parses a PDF file
# used by ppc_pdf2oplist
#


require 'zlib'

# a Virtual string backed by a file, which is read on-demand
class VString
	# creates a VString from a file
	def self.read(fname)
		raise 'need a PDF filename' if not fname
		new File.open(fname, 'rb'), File.size(fname)
	end

	def initialize(fd, len)
		@fd = fd
		@len = len
	end

	def length; @len end

	def [](start, len=nil)
		return if not start
		if start.kind_of? Range
			len = start.end
			len -= 1 if start.exclude_end?
			len = @len+1+len if len < 0
			start = start.begin
		end
		start = @len+1+start if start < 0
		return nil if start < 0 or len < 0 or start > @len
		@fd.pos = start
		@fd.read len
	end

	# search on a small region (1k or 1M)
	def index(sub, off=0)
		off += 1 + @len if off < 0
		return if not ret = self[off, 1024].index(sub) || self[off, 1024*1024].index(sub)
		ret + off
	end

	# search on a small region (1k or 1M)
	def rindex(sub, off=@len)
		off += 1 + @len if off < 0
		p1 = [off, 1024].min
		p2 = [off, 1024*1024].min
		if ret = self[off-p1, p1].rindex(sub)
		       ret + off-p1
		elsif p1 != p2 and ret = self[off-p2, p2].rindex(sub)
			ret + off-p2
		end
	end
end

# a PDF parser
class PDF
	attr_accessor :str, :off, :trailer, :hdr, :xrefs, :xoff

	# reads a filename as a PDF using VString
	def self.read(filename)
		new(VString.read(filename))
	end

	def initialize(str=nil)
		read str if str
	end

	# reads a string as a PDF, interpret basic informations (header, trailer, xref table)
	def read(str)
		@str = str
		@off = 0
		readhdr
		raise 'bad pdf: no trailer' unless @off = @str.rindex("trailer", @str.length)
		readtrailer
		self
	end

	def readhdr
		@hdr = @str[@off, @off = @str.index("\n", @off)]
	end

	# reads the pdf trailer
	# XXX the xref table referenced here may be the first of the file, so we suppose the last is just before the 'trailer' command..
	def readtrailer
		toff = @off
		readcmd
		@trailer = readhash
		readcmd
		@xroff = readint
		@xoff = {}	# [gen] => { id => off }
		@xrefs = {}	# [gen] => { id => obj }
		@off = @xroff
		readcmd
		readxrtable
		off2 = @off
		if @off < toff and readcmd == 'trailer' and off = @str.rindex('xref', toff)
			@off = off
			readcmd
			readxrtable
			@off = off2
			readcmd
			@trailer.update readhash
		end
	end

	def readxrtable
		while @str[@off, 7] != 'trailer'
			objnr = readint
			objcnt = readint
			@str[@off, 20*objcnt].scan(/(\d+) (\d+) (.)/) { |o, g, u|
				(@xoff[g.to_i] ||= {})[objnr] = o.to_i if u == 'n'
				objnr += 1
			}
			@off += 20*objcnt
			skipspc
		end
	end

	def readint
		buf = ''
		loop do
			case c = @str[@off, 1]
			when '+', '-'; break if not buf.empty?
			when '.'; break if buf.include? '.'
			when '0'..'9'
			else break
			end
			buf << c
			@off += 1
		end
		return if buf.empty?
		skipspc
		buf.include?('.') ? buf.to_f : buf.to_i
	end

	def readstr
		buf = ''
		case @str[@off, 1]
		when '('
			nest = 0
			loop do
				@off += 1
				case c = @str[@off, 1]
				when '('; nest += 1 ; buf << c
				when ')'; nest -= 1 ; break if nest < 0 ; buf << c
				when '\\'
					@off += 1
					case c = @str[@off, 1]
					when 'n'; buf << ?\n
					when 'r'; buf << ?\r
					when 't'; buf << ?\t
					when 'b'; buf << ?\b
					when '0'..'7'
						if ('0'..'7').include?(cc = @str[@off+1, 1])
						@off += 1 ; c << cc
						if ('0'..'7').include?(cc = @str[@off+1, 1])
						@off += 1 ; c << cc
						end
						end
						buf << c.to_i(8)
					when nil; break
					else buf << c
					end
				when nil; break
				else buf << c
				end
			end
		when '<'
			loop do
				@off += 1
				case c = @str[@off, 1]
				when '0'..'9', 'a'..'f', 'A'..'F'; buf << c
				when ' ', "\n", "\r", "\t"
				else break
				end
			end
			buf << '0' if buf.length % 2 == 1
			buf = [buf].pack('H*')
		else return
		end
		@off += 1
		skipspc
		buf
	end

	def readname
		return if @str[@off, 1] != '/'
		buf = ''
		loop do
			@off += 1
			case c = @str[@off, 1]
			when '#'; buf << @str[@off+1, 2].to_i(16) ; @off += 2
			when nil, /[\s\(\)\{\}<>\[\]\/]/; break
			else buf << c
			end
		end
		skipspc
		buf
	end

	def readarray
		return if @str[@off, 1] != '['
		buf = []
		@off += 1
		skipspc
		buf << readany until @str[@off, 1] == ']' or @off >= @str.length
		@off += 1
		skipspc
		buf
	end

	def readhash
		return if @str[@off, 2] != '<<'
		buf = {}
		@off += 2
		skipspc
		buf[readname] = readany until @str[@off, 2] == '>>' or @off >= @str.length
		buf.delete_if { |k, v| v == :null }
		@off += 2
		skipspc
		buf
	end

	def readcmd
		buf = ''
		loop do
			case c = @str[@off, 1]
			when nil, /[\s\(\)\{\}<>\[\]\/%]/; break
			else buf << c
			end
			@off += 1
		end
		skipspc
		buf
	end

	def newstream(hash, data)
		f = [hash['Filter']].flatten.compact
		if f.length == 1 and f.first == 'FlateDecode'
			data = Zlib::Inflate.inflate(data)
		elsif f.length == 0
		else	puts "stream filter #{f.inspect} unsupported"
		end
		hash[:data] = data
		hash
	end

	class Ref
		attr_accessor :gen, :id
		def initialize(pdf, gen, id)
			@pdf, @gen, @id = pdf, gen, id
		end

		def inspect
			"#<Ref @pdf=#{@pdf.object_id.to_s(16)} @gen=#@gen @id=#@id>"
		end

		def deref(depth=1)
			@pdf.deref(self, depth)
		end

		def method_missing(*a, &b)
			deref.send(*a, &b)
		end
	end

	# reads & returns any pdf object according to its 1st char (almost)
	# updates @xrefs if the object is indirect
	def readany
		case @str[@off, 1]
		when nil; return
		when '/'; readname
		when '+', '-'; readint
		when '0'..'9'
			i = readint
			if ('0'..'9').include?(@str[@off, 1])
				poff = @off
				g = readint
				case readcmd
				when 'obj'
					@xrefs[g] ||= {}
					i = @xrefs[g][i] ||= readany
					raise 'no endobj' if readcmd != 'endobj'
				when 'R'
					i = Ref.new(self, g, i)
				else @off = poff
				end
			end
			i
		when '['; readarray
		when '('; readstr
		when '<'
 			if @str[@off+1, 1] == '<'
				h = readhash
				if @str[@off, 6] == 'stream' and i = @str.index("\n", @off)	# readcmd may eat spaces that are part of the stream
					l = h['Length'].to_i
					h = newstream(h, @str[i+1, l])
					@off = i+1+l
					skipspc
					raise 'no endstream' if readcmd != 'endstream'
				end
				h
			else readstr
			end
		else
			case c = readcmd
			when 'true', 'false', 'null'; c.to_sym
			when 'xref'; readxrtable ; (@trailer ||= {}).update readhash if readcmd == 'trailer' ; readint if readcmd == 'startxref' ; :xref
			else raise "unknown cmd #{c.inspect}"
			end
		end
	end

	def skipspc
		while @off < @str.length
			case @str[@off, 1]
			when '%'; @off += 1 until @str[@off, 1] == "\n" or @off >= @str.length
			when ' ', "\n", "\r", "\t"
			else break
			end
			@off += 1
		end
	end

	# dereference references from the specified root, with the specified depth
	def deref(obj, depth=1)
		if obj.kind_of? Ref
			@xrefs[obj.gen] ||= {}
			if not nobj = @xrefs[obj.gen][obj.id]
				pvoff = @off
				raise 'unknown ref off' unless @off = @xoff[obj.gen][obj.id]
				puts "deref #{obj.gen} #{obj.id} => #{@off.to_s(16)}" if $DEBUG
				nobj = @xrefs[obj.gen][obj.id] = readany || :poil
				@off = pvoff
			end
			obj = nobj
		end
		depth -= 1
		case obj
		when Hash; obj = obj.dup ; obj.each { |k, v| obj[k] = deref(v, depth) }
		when Array; obj = obj.dup ; obj.each_with_index { |v, i| obj[i] = deref(v, depth) }
		end if depth > 0
		obj
	end

	# returns the :data field for a Hash or the concatenation of the :data fields of the children for an Array
	def page_data(ct)
		if deref(ct).kind_of? Array
			ct.map { |c| c[:data] }.join
		else
			ct[:data]
		end
	end

	# iterates over the PDF pages, yields each PSPage
	def each_page(h=@trailer['Root']['Pages'])
		if h['Kids']
			h['Kids'].each { |k| each_page(k, &Proc.new) }
		else
			yield PSPage.new(page_data(h['Contents']))
		end
	end

	# returns the nr-th page of the pdf as a PSPage
	def page(nr, ar=@trailer['Root']['Pages']['Kids'])
		ar.each { |kid|
			if kid['Count']
				break page(nr, kid['Kids']) if nr <= kid['Count']
				nr -= kid['Count']
			else
				nr -= 1
				break PSPage.new(page_data(kid['Contents'])) if nr <= 0
			end
		}
	end
end

# a PostScript page (lines with position information)
class PSPage
	class Line
		CHARWIDTH=400
		attr_accessor :str, :x, :y, :fontx, :fonty
		# parses a postscript line, returns a line with individual characters at the right place (more or less)
		def initialize(str, x, y, fontx, fonty, charspc, wordspc)
@raw, @charspc, @wordspc = str, charspc, wordspc
			@x, @y, @fontx, @fonty = x, y, fontx, fonty
			str = str[1...-1] if str[0] == ?[
			@str = ''
			bs = char = false
			#lastchar = nil
			spc = ''
			str.each_byte { |b|
				if not bs
				# special chars (unescaped)
				case b
				when ?(	# new word: honor word spacing
					spc = (-spc.to_f/CHARWIDTH).round
					if spc > 0 and not @str.empty?
						@str << (' '*spc)
					elsif spc < 0
						@str.chop! while @str[-1] == ?\  and (spc += 1) <= 0# and (lastchar != ?\  or @str[-2] == lastchar)
					end
					char = true
					next
				when ?\\	# bs character
					bs = true
					next
				when ?)	# end of word
					char = false
					spc = ''
					next
				end
				end

				# octal escape sequence: leave as is (actual char depends on font)
				if bs and (?0..?7).include? b; @str << ?\\ end

				bs = false
				if char
					# update current rendered string, honoring charspc
					@str << b
					@str << (' ' * (charspc*1000/CHARWIDTH).round) if charspc > 0.1
					@str << (' ' * (wordspc*1000/CHARWIDTH).round) if b == ?\  and wordspc > 0.1
					#lastchar = b
				else
					# between strings: store word spacing integer
					spc << b
				end
			}
puts "(#{x}, #{y} #{fontx}, #{fonty}) #@str" if $VERBOSE
		end
		def to_s ; @str end
	end

	attr_accessor :lines
	def initialize(str=nil)
		parse(str) if str
	end

	# remove lines not within ymin and ymax
	def clip_lines(ymin, ymax)
		ymin, ymax = ymax, ymin if ymin > ymax
		@lines.each { |la| la.delete_if { |l| l.y < ymin or l.y > ymax } }
		@lines.delete_if { |la| la.empty? }
		self
	end

	# parse a postscript string to an array of paragraph (itself an array of lines)
	# handles text strings and basic cursor position updates
	def parse(str)
		@lines = []
		curx = cury = 0
		fontx = fonty = 12
		charspc = wordspc = 0
		stack = []
		linelead = -12
		ps2tok(str) { |t|
case t
when Float, String; print "#{t} "
else puts t
end if $VERBOSE
			case t
			when Float, String; stack << t		# be postfix !
			when :BT; intext = true ; @lines << []	# begin text
			when :ET; intext = false		# end text
			when :Tj, :TJ	# print line
				@lines.last << Line.new(stack.pop, curx, cury, fontx, fonty, charspc, wordspc)
			when :Td, :TD	# move cursor
				linelead = stack.last*fonty if t == :TD
				cury += stack.pop*fonty
				curx += stack.pop*fontx
			when :'T*'	# new line
				cury += linelead
			when :Tc	# character spacing
				# RHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				#3.17731 Tc 9 0 0 9 343.41 653.84998 Tm
				#[(3T)3202(O)729(R)3179(A)-3689(S)3178(I)]TJ
				# => 3    TO     RA             SI
				charspc = stack.pop
			when :Tw
				wordspc = stack.pop
			when :Tm	# set transform matrix (scale, rotate, translate)
				params = Array.new(6) { stack.pop }.reverse
				next if params[0] == 0.0	# rotated text
				fontx, _, _, fonty, curx, cury = params
			end
		}
	end

	# yields PS tokens: floats, commands, and strings
	def ps2tok(str)
		loop do
			case str
			when ''; break
			when /\A-?\d+(?:\.\d+)?/; tok = $&.to_f
			when /\A\((?:\\.|[^\\)])*\)/; tok = $&
			when /\A\[(?:[^\](]*\((?:\\.|[^\\)])*\))*[^\]]*\]/; tok = $&
			when /\A[a-zA-Z0-9_*]+/; tok = $&.to_sym rescue nil
			when /\A\S+/, /\A\s+/
			end
			str = str[$&.length..-1]
			yield tok if tok
		end
	end

	# renders the lines, according to the layout (almost ;) )
	def to_s
		mx = @lines.flatten.map { |l| l.x }.min
		py = nil
		strs = ['']
		@lines.sort_by { |la| -la.map { |l| l.y }.max.to_i }.each { |la|
		y = la.map { |l| l.y }.max
		strs.concat ['']*((py-y)/12) if py and py > y
		la.sort_by { |l| [-l.y, l.x] }.each { |l|
			# 9 == base font size
			strs << '' if y > l.y+l.fonty*0.9 or strs.last.length*1000/Line::CHARWIDTH/9 > l.x-mx
			strs[-1] = strs.last.ljust((l.x-mx)*1000/Line::CHARWIDTH/9-1) << ' ' << l.str
			y = l.y
		}
		py = y if not py or py > y
		}
		strs.join("\n")
	end
end

if __FILE__ == $0
require 'pp'
begin
	pdf = PDF.read ARGV.shift

	if $VERBOSE
	puts 'Info: '
	pp pdf.deref(pdf.trailer['Info'])
	puts
	end

	if not ARGV.empty?
		ARGV.each { |pagenr|
			puts pdf.page(pagenr.to_i)
		}
	else
		puts 'Pages: '
		pagecnt = 0
		pdf.each_page { |page|
			pagecnt += 1
			puts "         ------- p.#{pagecnt} ---------", page
		}
	end
rescue
	puts "at #{pdf.off.to_s(16) if pdf}", $!, $!.backtrace[0, 24]
end
end

__END__
PostScript text formatting, shamelessly ripped from the web (http://www.mactech.com/articles/mactech/Vol.15/15.09/PDFIntro/)

Object 3, which contains the contents of page one of our document, is worth commenting on since it shows how text streams are used in PDF. The object looks like:

3 0 obj
<<
/Length 168
>>
stream
BT
/F4 1 Tf
12 0 0 12 50.64 731.52 Tm
0 0 0 rg
BX /GS2 gs EX
0 Tc
0 Tw
@charspc = charspc
[(This is 12-point )10(T)41(imes. )
	18(This sentence will appear near
	the top of page one.)]TJ
ET
endstream
endobj

The stream object (which is 168 bytes long) is bracketed by BT and ET operators, for Begin Text and End Text. The Tf command selects our font and its size in user-space units, which is given as 1. "But aren't we using 12-point type?" you may be wondering. Yes, we are. That's specified in the next line, ending in Tm (which is the set-text-matrix operator). For space reasons, we won't say much about coordinate system transformations and matrices here, but if you're familiar with the use of matrices in PostScript, the same rules apply in PDF. A transform matrix is given by an array of six numbers, the first and fourth of which determine scaling in x and y, respectively. We see in our text matrix, the scaling factor is 12. That means we will use 12-point type. The last two numbers in the matrix (50.64 and 731.52) specify a translation, in user-space units. The effect of the translation is to put our text approximately 10.1 inches high on the page, with a left margin of 0.7 inch.

The line ending with rg sets our ink color to an RGB value of 0 0 0, or black. The BX operator says that we are beginning a section that allows undefined operators. In this section, we apply the gs operator (which sets parameters in the extended graphics state), using /GS2 as our EGS specifications. The EX operator ends the section allowing undefined operators. In essence, we're saying "Any reading application that understands what's in this special section can execute the instructions contained there, but if you don't understand the instructions, just go on." The reason this section has to be handled this way is that extended graphics state instructions often contain device-dependent instructions. The lack of generality means we should bracket those instructions with BX/EX.

The Tc and Tw operators are for setting character spacing and word spacing, respectively.

Finally, we come to the text that will be displayed on our page. Oddly enough, it's specified in an array of text snippets interspersed with integers, such as:

(This is 12-point )10(T)41(imes. )

The number 10 represents a kerning value, in thousandths of an em. (An em is a typographical unit of measurement equal to the size of the font.) This number is subtracted from the 'x' coordinate of the letter(s) that follow, displacing the text to the left. The capital 'T' is displaced 10 units to the left, while "imes. " is displaced 41 units. The TJ at the end of the array is the operator for "show text, allowing individual character spacing."

Finally, ET closes off the text block, and endstream closes off the stream.

b 	closepath, fill,and stroke path.
B 	fill and stroke path.
b* 	closepath, eofill,and stroke path.
B* 	eofill and stroke path.
BI 	begin image.
BMC 	begin marked content.
BT 	begin text object.
BX 	begin section allowing undefined operators.
c 	curveto.
cm 	concat. Concatenates the matrix to the current transform.
cs 	setcolorspace for fill.
CS 	setcolorspace for stroke.
d 	setdash.
Do 	execute the named XObject.
DP 	mark a place in the content stream, with a dictionary.
EI 	end image.
EMC 	end marked content.
ET 	end text object.
EX 	end section that allows undefined operators.
f 	fill path.
f* 	eofill Even/odd fill path.
g 	setgray (fill).
G 	setgray (stroke).
gs 	set parameters in the extended graphics state.
h 	closepath.
i	setflat.
ID 	begin image data.
j 	setlinejoin.
J 	setlinecap.
k 	setcmykcolor (fill).
K 	setcmykcolor (stroke).
l 	lineto.
m 	moveto.
M 	setmiterlimit.
n 	end path without fill or stroke.
q 	save graphics state.
Q 	restore graphics state.
re 	rectangle.
rg 	setrgbcolor (fill).
RG 	setrgbcolor (stroke).
s 	closepath and stroke path.
S 	stroke path.
sc 	setcolor (fill).
SC 	setcolor (stroke).
sh 	shfill (shaded fill).
Tc 	set character spacing.
Td 	move text current point.
TD 	move text current point and set leading.
Tf 	set font name and size.
Tj 	show text.
TJ 	show text, allowing individual character positioning.
TL 	set leading.
Tm 	set text matrix.
Tr 	set text rendering mode.
Ts 	set super/subscripting text rise.
Tw	set word spacing.
Tz 	set horizontal scaling.
T* 	move to start of next line.
v 	curveto.
w 	setlinewidth.
W 	clip.
y 	curveto.
