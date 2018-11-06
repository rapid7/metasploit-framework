require 'readline'

loop do
  line = Readline::readline('> ')
  Readline::HISTORY.push(line)
  puts "You typed: #{line}"
  break if line == 'quit'
end
