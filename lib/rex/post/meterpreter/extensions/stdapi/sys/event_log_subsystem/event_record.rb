#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module EventLogSubsystem

###
#
# This class encapsulates the data from an event log record.
#
###
class EventRecord

  attr_reader :num, :generated, :written, :eventid
  attr_reader :type, :category, :strings, :data

  protected

  attr_writer :num, :generated, :written, :eventid
  attr_writer :type, :category, :strings, :data

  public

  def initialize(recnum, timegen, timewri, id, type, cat, strs, data)
    self.num       = recnum
    self.generated = Time.at(timegen)
    self.written   = Time.at(timewri)
    self.eventid   = id
    self.type      = type
    self.category  = cat
    self.strings   = strs
    self.data      = data
  end

end

end end end end end end end
