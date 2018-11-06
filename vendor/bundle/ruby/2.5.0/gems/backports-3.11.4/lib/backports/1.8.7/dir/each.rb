require 'backports/tools/make_block_optional'

begin
  Backports.make_block_optional Dir, :each, :test_on => Dir.new('.')
rescue # We may not be able to read the current directory, issue #58
  Backports.make_block_optional Dir, :each, :force => true if RUBY_VERSION < '1.8.7'
end
