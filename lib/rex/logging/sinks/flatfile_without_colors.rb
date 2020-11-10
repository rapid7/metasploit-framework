# -*- coding: binary -*-
module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against a
# file on disk. The logged messages will have their colors and trailing
# whitespace removed
#
###
class FlatfileWithoutColors < Flatfile

  def log(sev, src, level, msg) # :nodoc:
    return unless msg.present?
    msg = msg.gsub(/\x1b\[[0-9;]*[mG]/,'').gsub(/[\x01-\x02]/, ' ').gsub(/\s+$/,'')
    stream.write("[#{get_current_timestamp}] #{msg}\n")
    stream.flush
  end
end

end end end
