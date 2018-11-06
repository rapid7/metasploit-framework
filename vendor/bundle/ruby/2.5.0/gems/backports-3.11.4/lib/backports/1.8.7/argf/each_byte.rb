if RUBY_VERSION < '1.8.7'
  require 'backports/tools/make_block_optional'

  class << ARGF
    Backports.make_block_optional ARGF, :each_byte, :force => true

    alias_method :bytes, :each_byte
  end
end
