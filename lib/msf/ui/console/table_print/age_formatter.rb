# -*- coding: binary -*-

class Msf::Ui::Console::TablePrint::AgeFormatter
  # Takes a string representation of a Time and attempts to parse it
  # using a heuristic. The duration is then calculated, and returned
  # in a human readable format, such as '13m' to represent 13 minutes ago.
  #
  # @param [String] date A date string, preferably in an iso8601 format
  def format(date)
    begin
      duration = (Time.now - Time.parse(date))
    rescue ArgumentError
      return format_invalid_date(date)
    end
    seconds = duration
    minutes = seconds / 60
    hours = duration / (60 * 60)
    days = duration / (60 * 60 * 24)
    years = duration / (60 * 60 * 24 * 365)

    if seconds < -1
      format_invalid_date(date)
    elsif seconds < 0
      '0s'
    elsif seconds < 60 * 2
      "#{seconds.to_i}s"
    elsif minutes < 10
      seconds = duration.to_i % 60
      "#{minutes.to_i}m#{seconds == 0 ? '' : "#{seconds}s"}"
    elsif minutes < 60 * 3
      "#{minutes.to_i}m"
    elsif hours < 8
      minutes = minutes.to_i % 60
      "#{hours.to_i}h#{minutes == 0 ? '' : "#{minutes}m"}"
    elsif hours < 24 * 2
      "#{hours.to_i}h"
    elsif hours < 24 * 8
      hours = hours.to_i % 24
      "#{days.to_i}d#{hours == 0 ? '' : "#{hours}h"}"
    elsif hours < 24 * 365 * 2
      "#{days.to_i}d"
    elsif hours < 24 * 365 * 8
      days = days % 365
      "#{years.to_i}y#{days == 0 ? '' : "#{days.to_i}d"}"
    else
      "#{years.to_i}y"
    end
  end

  protected

  def format_invalid_date(_date)
    "<invalid>"
  end
end
