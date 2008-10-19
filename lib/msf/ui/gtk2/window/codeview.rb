module Msf
module Ui
module Gtk2

class MsfWindow

	#
	# This class performs a Gtk::Window to display logs from framework
	#
	class CodeView < Msf::Ui::Gtk2::SkeletonBasic

		

		include Msf::Ui::Gtk2::MyControls

		def initialize(m)

			# call the parent
			super("View Source: #{m.file_path}")

			# Define the size and border
			set_default_size(600, 480)
			set_border_width(1)

			# Main hbox
			vbox = Gtk::VBox.new(false, 0)
			add(vbox)

			textview = Gtk::TextView.new
			textview.set_editable(false)

			sw = Gtk::ScrolledWindow.new()
			sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
			vbox.pack_start(sw, true, true, 0)

			sw.add(textview)


			buff = textview.buffer
			fixr = buff.create_tag("fixr", 
				{ 
					"font" => "Courier"
				}
			)
	

			font_desc = Pango::FontDescription.new('Courier 10')
			textview.modify_font(font_desc)
			
		
			buff.create_tag('comment', {'foreground' => 'DarkGray'})
			buff.create_tag('const', {'foreground' => 'DarkGreen'})
			buff.create_tag('method', {'foreground' => 'DarkRed'})
			buff.create_tag('string', {
				'foreground' => 'DarkBlue',
				'weight' => Pango::FontDescription::WEIGHT_BOLD
			})

			buff.create_tag('reserved', {'foreground' => 'purple'})

		
			buff.insert(buff.start_iter, File.read(m.file_path))
			
			start_iter = buff.start_iter
			end_iter = buff.end_iter
			str = buff.get_text(start_iter, end_iter, true)

			tokenizer = RubyTokenizer.new
			tokenizer.tokenize(str, start_iter.offset) do |tag, start, last|
				buff.apply_tag(
					tag.to_s,
					buff.get_iter_at_offset(start),
					buff.get_iter_at_offset(last)
				)
			end
	
			show_all
		end


		#
		# Pulled from ruby-gtk2 / gtk-demo (under Ruby license)
		# Modified to work better with MSF module source
		#
		class RubyTokenizer
			RESERVED_WORDS = %w(begin end module class def if then else while unless do case when require yield)
			RESERVED_WORDS_PATTERN = Regexp.compile(/(^|\s+)(#{RESERVED_WORDS.collect do |pat| Regexp.quote(pat) end.join('|')})(\s+|$)/)

			def tokenize(str, index = 0)
				until str.empty?
					tag = nil

					case str
					when /".+?"/, /'.+?'/
						tag = :string
					when /#.*$/
						tag = :comment
					when RESERVED_WORDS_PATTERN
						tag = :reserved
					when /[A-Za-z0-9_]+\(|\)/
						tag = :method
					when /[A-Z0-9][A-Za-z0-9_]+|false|true/
						tag = :const
					end

					if tag
						tokenize($~.pre_match, index) do |*args|
    						yield(*args)
						end

						yield(tag, index + $~.begin(0), index + $~.end(0))

						index += (str.length - $~.post_match.length)
						str = $~.post_match
					else
						index += str.length
						str = ''
					end
				end
			end
		end
		
	end

end

end
end
end