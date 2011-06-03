require 'rkelly/constants'
require 'rkelly/visitable'
require 'rkelly/visitors'
require 'rkelly/parser'
require 'rkelly/runtime'
require 'rkelly/syntax_error'

module RKelly
  class << self
    def parse *args
      RKelly::Parser.new.parse(*args)
    end
  end
end
