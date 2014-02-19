#!/usr/bin/ruby -w

require 'getoptlong'

def	help
  puts "Usage: #{$0} [options]"
  puts "\t-h --help\t\tthis help."
  puts "\t-f --file\t\toutput file."
  puts "\t-n --num\t\tcharset: 0123456789"
  puts "\t-a --alpha\t\tcharset: abcdefghijklmnopqrstuvwxyz"
  puts "\t-A --alphamaj\t\tcharset: ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  puts "\t-l --alphanum\t\tcharset: alpha + num"
  puts "\t-l --alphanummaj\tcharset: alpha + alphamaj + num"
  puts "\t-s --all\t\tcharset: alpha + alphamaj + num + !@#$+=.*"
  puts "\t-c --custom"
  puts "\nExample:\n"
  puts "#{$0} -f stats -s"
  puts "#{$0} -f stats -c \"0123abc+=\""
  exit
end

ch_alpha 	= 'abcdefghijklmnopqrstuvwxyz'
ch_num 		= '0123456789'
ch_sp		= '!@#$+=.*'

opts = GetoptLong.new(
  [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
  [ '--file', '-f', GetoptLong::OPTIONAL_ARGUMENT],
  [ '--all', '-s', GetoptLong::NO_ARGUMENT],
  [ '--num', '-n', GetoptLong::NO_ARGUMENT],
  [ '--alpha', '-a', GetoptLong::NO_ARGUMENT ],
  [ '--alphamaj', '-A', GetoptLong::NO_ARGUMENT ],
  [ '--alphanum', '-l', GetoptLong::NO_ARGUMENT ],
  [ '--alphanummaj', '-L', GetoptLong::NO_ARGUMENT ],
  [ '--custom', '-c', GetoptLong::OPTIONAL_ARGUMENT ]
)

charset = nil
filename = "stats_out"

opts.each do |opt, arg|
  case opt
  when '--help'
    help
  when '--file'
    filename = arg
  when '--num'
    charset = ch_num
  when '--alpha'
    charset = ch_alpha
  when '--alphamaj'
    charset = ch_alpha.capitalize
  when '--alphanum'
    charset = ch_alpha + ch_num
  when '--alphanummaj'
    charset = ch_alpha.capitalize + ch_num
  when '--all'
    charset = ch_alpha + ch_alpha.capitalize + ch_num + ch_sp
  when '--custom'
    charset = arg
  end
end


if charset == nil
  help
end


fstat = File.open(filename, "w")
charset.each_byte do |c|
  fstat.write("1=proba1[#{c.to_s}]\n")
  charset.each_byte do |tmp|
    fstat.write("1=proba2[#{c.to_s}*256+#{tmp.to_s}]\n")
  end
end
fstat.close

