# -*- coding: binary -*-
module Rex
module Proto
module SMB
class Evasions

require 'rex/text'

EVASION_NONE  = 0
EVASION_LOW   = 1
EVASION_HIGH  = 2
EVASION_MAX   = 3

  # Add bogus filler at the end of the SMB packet and before the data
  def self.make_offset_filler(level, max_size = 60000, min_size = 512)

    if (max_size < 0)
      max_size = 4096
    end

    if (min_size < max_size)
      min_size = max_size - 1
    end

    case level.to_i
      when EVASION_LOW
        Rex::Text.rand_text(32)
      when EVASION_HIGH
        Rex::Text.rand_text( rand(max_size - min_size) + min_size )
      when EVASION_MAX
        Rex::Text.rand_text( rand(max_size) )
      else EVASION_NONE
        return ''
    end
  end

  # Obscures a named pipe pathname via leading and trailing slashes
  def self.make_named_pipe_path(level, pipe)
    case level.to_i
      when EVASION_LOW
        return ('\\' * (1024 + rand(512))) + pipe
      when EVASION_HIGH, EVASION_MAX
        return ('\\' * (1024 + rand(512))) + pipe + ('\\' * (1024 + rand(512)))
      else
        return '\\' + pipe
    end
  end

  # Obscures the TransactNamedPipe \PIPE\ string
  def self.make_trans_named_pipe_name(level)
    case level.to_i
      when EVASION_LOW
        return ('\\' * (256 - rand(64)) + 'PIPE\\')
      when EVASION_HIGH
        return Rex::Text.rand_text(512 - rand(128))
      when EVASION_MAX
        return Rex::Text.rand_text(1024 - rand(256))
      else
        return '\\PIPE\\'
    end
  end

end
end
end
end

