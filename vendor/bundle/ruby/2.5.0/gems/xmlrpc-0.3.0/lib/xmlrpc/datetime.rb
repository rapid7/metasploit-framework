# frozen_string_literal: false
#
# xmlrpc/datetime.rb
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# Released under the same term of license as Ruby.
#
require "date"

module XMLRPC # :nodoc:

# This class is important to handle XMLRPC +dateTime.iso8601+ values,
# correctly, because normal UNIX-dates, ie: Date, only handle dates
# from year 1970 on, and ruby's native Time class handles dates without the
# time component.
#
# XMLRPC::DateTime is able to store a XMLRPC +dateTime.iso8601+ value correctly.
class DateTime

  # Return the value of the specified date/time component.
  attr_reader :year, :month, :day, :hour, :min, :sec

  # Set +value+ as the new date/time component.
  #
  # Raises ArgumentError if the given +value+ is out of range, or in the case
  # of XMLRPC::DateTime#year= if +value+ is not of type Integer.
  def year=(value)
    raise ArgumentError, "date/time out of range" unless value.is_a? Integer
    @year = value
  end

  # Set +value+ as the new date/time component.
  #
  # Raises an ArgumentError if the given +value+ isn't between 1 and 12.
  def month=(value)
    raise ArgumentError, "date/time out of range" unless (1..12).include? value
    @month = value
  end

  # Set +value+ as the new date/time component.
  #
  # Raises an ArgumentError if the given +value+ isn't between 1 and 31.
  def day=(value)
    raise ArgumentError, "date/time out of range" unless (1..31).include? value
    @day = value
  end

  # Set +value+ as the new date/time component.
  #
  # Raises an ArgumentError if the given +value+ isn't between 0 and 24.
  def hour=(value)
    raise ArgumentError, "date/time out of range" unless (0..24).include? value
    @hour = value
  end

  # Set +value+ as the new date/time component.
  #
  # Raises an ArgumentError if the given +value+ isn't between 0 and 59.
  def min=(value)
    raise ArgumentError, "date/time out of range" unless (0..59).include? value
    @min = value
  end

  # Set +value+ as the new date/time component.
  #
  # Raises an ArgumentError if the given +value+ isn't between 0 and 59.
  def sec=(value)
    raise ArgumentError, "date/time out of range" unless (0..59).include? value
    @sec = value
  end

  # Alias for XMLRPC::DateTime#month.
  alias mon  month
  # Alias for XMLRPC::DateTime#month=.
  alias mon= month=


  # Creates a new XMLRPC::DateTime instance with the
  # parameters +year+, +month+, +day+ as date and
  # +hour+, +min+, +sec+ as time.
  #
  # Raises an ArgumentError if a parameter is out of range,
  # or if +year+ is not of the Integer type.
  def initialize(year, month, day, hour, min, sec)
    self.year, self.month, self.day = year, month, day
    self.hour, self.min, self.sec   = hour, min, sec
  end

  # Return a Time object of the date/time which represents +self+.
  #
  # The timezone used is GMT.
  def to_time
    Time.gm(*to_a)
  end

  # Return a Date object of the date which represents +self+.
  #
  # The Date object do _not_ contain the time component (only date).
  def to_date
    Date.new(*to_a[0,3])
  end

  # Returns all date/time components in an array.
  #
  # Returns +[year, month, day, hour, min, sec]+.
  def to_a
    [@year, @month, @day, @hour, @min, @sec]
  end

  # Returns whether or not all date/time components are an array.
  def ==(o)
    self.to_a == Array(o) rescue false
  end

end


end # module XMLRPC


=begin
= History
    $Id$
=end
