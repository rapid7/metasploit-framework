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
class TimestampColorlessFlatfile < Flatfile
  def log(sev, src, level, msg) # :nodoc:
    return unless msg.present?
    if sev == LOG_RAW
      msg = msg.gsub(/\x1b\[[0-9;]*[mG]/,'').gsub(/[\x01-\x02]/, ' ').gsub(/\s+$/,'')
      msg = "[#{get_current_timestamp}] #{msg}\n"
    end
    super(sev, src, level, msg)
  end
end

end end end
