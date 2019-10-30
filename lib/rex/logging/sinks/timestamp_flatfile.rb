# -*- coding: binary -*-
module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against a
# file on disk with a Timestamp.
#
###
class TimestampFlatfile < Flatfile

  def log(sev, src, level, msg, from) # :nodoc:
    return unless msg.present?
    msg = msg.gsub(/\x1b\[[0-9;]*[mG]/,'').gsub(/[\x01-\x02]/, ' ').gsub(/\s+$/,'')
    fd.write("[#{get_current_timestamp}] #{msg}\n")
    fd.flush
  end
end

end end end
