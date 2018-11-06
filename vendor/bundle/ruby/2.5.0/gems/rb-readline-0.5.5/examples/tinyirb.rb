require 'readline.rb'

loop do
  line = Readline::readline('> ')
  Readline::HISTORY.push(line)
  puts "You typed: #{line}"

  if line =~ /exit|quit/ then
    exit
  end
end
