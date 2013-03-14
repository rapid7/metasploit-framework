module Treetop
  module Polyglot
    VALID_GRAMMAR_EXT = ['treetop', 'tt']
    VALID_GRAMMAR_EXT_REGEXP = /\.(#{VALID_GRAMMAR_EXT.join('|')})\Z/o
  end
end

require 'polyglot'
Polyglot.register(Treetop::Polyglot::VALID_GRAMMAR_EXT, Treetop)
