require 'readline'

list = [
  'search', 'download', 'open',
  'help', 'history', 'quit',
  'url', 'next', 'clear',
  'prev', 'past',
].sort

comp = proc{ |s| list.grep( /^#{Regexp.escape(s)}/) }

Readline.completion_append_character = " "
Readline.completion_proc = comp

while line = Readline.readline('> ', true)
  p line
  break if line == 'quit'
end
