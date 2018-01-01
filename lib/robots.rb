#
#  Copyright (c) 2008 Kyle Maxwell, contributors
#
#  Permission is hereby granted, free of charge, to any person
#  obtaining a copy of this software and associated documentation
#  files (the "Software"), to deal in the Software without
#  restriction, including without limitation the rights to use,
#  copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the
#  Software is furnished to do so, subject to the following
#  conditions:
#
#  The above copyright notice and this permission notice shall be
#  included in all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
#  OTHER DEALINGS IN THE SOFTWARE.
#

require "open-uri"
require "uri"
require "timeout"
require 'rex/logging/log_dispatcher'

# https://github.com/fizx/robots
class Robots
  DEFAULT_TIMEOUT = 3

  # Represents a parsed robots.txt file
  class ParsedRobots
    def initialize(uri, user_agent)
      @last_accessed = Time.at(1)

      io = Robots.get_robots_txt(uri, user_agent)

      if !io || io.content_type != "text/plain" || io.status.first != "200"
        io = StringIO.new("User-agent: *\nAllow: /\n")
      end

      @other = {}
      @disallows = {}
      @allows = {}
      @delays = {} # added delays to make it work
      agent = /.*/
      io.each do |line|
        next if line =~ /^\s*(#.*|$)/
        arr = line.split(":")
        key = arr.shift.to_s.downcase
        value = arr.join(":").strip
        value.strip!
        case key
        when "user-agent"
          agent = to_regex(value)
        when "allow"
          @allows[agent] ||= []
          @allows[agent] << to_regex(value)
        when "disallow"
          @disallows[agent] ||= []
          @disallows[agent] << to_regex(value)
        when "crawl-delay"
          @delays[agent] = value.to_i
        else
          @other[key] ||= []
          @other[key] << value
        end
      end

      @parsed = true
    end

    def allowed?(uri, user_agent)
      return true unless @parsed
      allowed = true
      path = uri.request_uri

      @disallows.each do |key, value|
        if user_agent =~ key
          value.each do |rule|
            allowed = false if path =~ rule
          end
        end
      end

      @allows.each do |key, value|
        unless allowed
          if user_agent =~ key
            value.each do |rule|
              if path =~ rule
                allowed = true
              end
            end
          end
        end
      end

      if allowed && @delays[user_agent]
        sleep @delays[user_agent] - (Time.now - @last_accessed)
        @last_accessed = Time.now
      end

      return allowed
    end

    def other_values
      @other
    end

    protected

    def to_regex(pattern)
      return /should-not-match-anything-123456789/ if pattern.strip.empty?
      pattern = Regexp.escape(pattern)
      pattern.gsub!(Regexp.escape("*"), ".*")
      Regexp.compile("^#{pattern}")
    end
  end

  def self.get_robots_txt(uri, user_agent)
    begin
      Timeout.timeout(Robots.timeout) do
        begin
          URI.join(uri.to_s, "/robots.txt").open("User-Agent" => user_agent)
        rescue StandardError
          nil
        end
      end
    rescue Timeout::Error
      dlog("robots.txt request timed out")
    end
  end

  attr_writer :timeout

  def self.timeout
    @timeout || DEFAULT_TIMEOUT
  end

  def initialize(user_agent)
    @user_agent = user_agent
    @parsed = {}
  end

  def allowed?(uri)
    uri = URI.parse(uri.to_s) unless uri.is_a?(URI)
    host = uri.host
    @parsed[host] ||= ParsedRobots.new(uri, @user_agent)
    @parsed[host].allowed?(uri, @user_agent)
  end

  def other_values(uri)
    uri = URI.parse(uri.to_s) unless uri.is_a?(URI)
    host = uri.host
    @parsed[host] ||= ParsedRobots.new(uri, @user_agent)
    @parsed[host].other_values
  end
end
