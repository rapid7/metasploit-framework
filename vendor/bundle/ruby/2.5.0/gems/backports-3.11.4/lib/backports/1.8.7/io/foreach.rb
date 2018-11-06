if RUBY_VERSION < '1.8.7'
  require 'backports/tools/make_block_optional'

  class << IO
    Backports.make_block_optional self, :foreach, :force => true
  end
end
