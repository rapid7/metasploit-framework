#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this file loads all metasm files, to avoid using ruby autoload mechanism

require File.join(File.dirname(__FILE__), '..', 'metasm')

module Metasm
  Const_autorequire.values.flatten.each { |f| require File.join('metasm', f) }
  $:.pop if $:.last == Metasmdir
end
