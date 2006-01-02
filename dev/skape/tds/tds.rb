$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))

require 'date'
require 'time'
require 'rex'
require 'rex/exploitation/opcodedb'

tds    = File.new('tds.txt', "r")
efile  = File.new('1970epoch.csv', "r")
epochs = Hash.new

begin
	while (line = efile.readline)
		ig, v_stamp, ig, ig, optype, v_duration = line.split(/,/)

		v_stamp  = v_stamp.to_i
		h_key    = v_stamp & 0xffff0000
		stamp    = Time.at(v_stamp)
		duration = Rex::ExtTime.str_to_sec(v_duration)

		epochs[h_key] = Array.new if (epochs[h_key] == nil)
		epochs[h_key] << [ stamp, v_stamp, v_stamp + duration, duration, optype ]
	end
rescue EOFError
ensure
	efile.close
end


begin
	while (line = tds.readline)
		line.chomp

		fields  = line.match(/^\s+?(\d+?)\s+\|\s+(.*)/).to_a

		next if fields.length == 0

		stamp   = Time.parse(fields[2].chomp)
		v_stamp = stamp.to_i

		if (ent = epochs[v_stamp & 0xffff0000])
			ent.each { |op|
				if (v_stamp >= op[1] and v_stamp < op[2])
					puts "#{fields[1]}: match #{op[4]}"
				end
			}
		end
	end
rescue EOFError
ensure
	tds.close
end
