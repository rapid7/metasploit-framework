require 'backports/tools/make_block_optional'

class << Dir
  begin
    Backports.make_block_optional self, :foreach, :test_on => Dir, :arg => '.'
  rescue # We may not be able to read the current directory, issue #58
    Backports.make_block_optional self, :foreach, :force => true if RUBY_VERSION < '1.8.7'
  end
end
