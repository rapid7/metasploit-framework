# -*- coding: binary -*-
module Msf
class Post
module Windows

module Eventlog

  #
  # Enumerate eventlogs
  #
  def eventlog_list
    key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
    if session.sys.config.sysinfo['OS'] =~ /Windows 2003|.Net|XP|2000/
      key = "#{key}Eventlog"
    else
      key = "#{key}eventlog"
    end
    eventlogs = registry_enumkeys(key)
    return eventlogs
  end

  #
  # Clears a given eventlog or all eventlogs if none is given. Returns an array of eventlogs
  # that where cleared.
  #
  def eventlog_clear(evt = "")
    evntlog = []
    if evt.empty?
      evntlog = eventloglist
    else
      evntlog << evt
    end
    evntlog.each do |e|
      log = session.sys.eventlog.open(e)
      log.clear
    end
    return evntlog
  end


end
end
end
end
