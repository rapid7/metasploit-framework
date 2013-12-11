# -*- coding: binary -*-

module Rex
module MachParsey

class MachError < ::RuntimeError
end

class MachParseError < MachError
end

class MachHeaderError < MachParseError
end

class ProgramHeaderError < MachParseError
end

class BoundsError < MachError
end

#class WtfError < MachError
#end

class FatError < ::RuntimeError
end

class FatParseError < FatError
end

class FatHeaderError < FatParseError
end

end
end
