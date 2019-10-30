# -*- coding: binary -*-

require 'rubygems/package'

module Rex::Tar
  class Reader < Gem::Package::TarReader; end
  class Writer < Gem::Package::TarWriter; end
end
