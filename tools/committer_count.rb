#!/usr/bin/env ruby

# The committer_count.rb is a way to tell who's been active over the last
# given period. It's of course, quite coarse -- someone with 10 commits in a day
# may or may not be more productive than someone with 3, but over long enough
# periods, it's an okay metric to measure involvement with the project, since
# large and small commits will tend to average out.
#
# Note that this includes merge commits by default (which usually means at least
# code review happened, so it's still a measure of work). You can get different
# stats by ignoring merge commits, once option parsing is implemented.
#
# Usage: ./committer_count.rb 2011-01-01 | head -10 # Since a particular date
#        ./committer_count.rb 1y   | head -10       # Last year
#        ./committer_count.rb 6m   | head -10       # Last six months
#        ./committer_count.rb 12w  | head -10       # Last twelve weeks
#        ./committer_count.rb 100d | head -10       # Last hundred days
#
#
# History with colors and e-mail addresses (respecting .mailmap):
# git log --pretty=format:"%C(white)%ad %C(yellow)%h %Cblue'%aN' <%aE> %Cgreen%f%Creset" --date=short

class GitLogLine < Struct.new(:date, :hash, :author, :message)
end

@history = `git log --pretty=format:"%ad %h '%aN' %f" --date=short --date-order`
@recent_history = []
@commits_by_author = {}

def parse_date(date)
  case date
  when /([0-9]+)y(ear)?s?/
    seconds = $1.to_i* (60*60*24*365.25)
    calc_date = (Time.now - seconds).strftime("%Y-%m-%d")
  when /([0-9]+)m(onth)?s?/
    seconds = $1.to_i* (60*60*24*(365.25 / 12))
    calc_date = (Time.now - seconds).strftime("%Y-%m-%d")
  when /([0-9]+)w(eek)?s?/
    seconds = $1.to_i* (60*60*24*7)
    calc_date = (Time.now - seconds).strftime("%Y-%m-%d")
  when /([0-9]+)d(ay)?s?/
    seconds = $1.to_i* (60*60*24)
    calc_date = (Time.now - seconds).strftime("%Y-%m-%d")
  else
    calc_date = Time.new(date).strftime("%Y-%m-%d")
  end
end

date = ARGV[0] || "2005-03-22" # A day before the first SVN commit.
calc_date = parse_date(date)

@history.each_line do |line|
  parsed_line = line.match(/^([^\s+]+)\s(.{7,})\s'(.*)'\s(.*)[\r\n]*$/)
  next unless parsed_line
  break if calc_date == parsed_line[1]
  @recent_history << GitLogLine.new(*parsed_line[1,4])
end

@recent_history.each do |logline|
  @commits_by_author[logline.author] ||= []
  @commits_by_author[logline.author] << logline.message
end

puts "Commits since #{calc_date}"
puts "-" * 50

@commits_by_author.sort_by {|k,v| v.size}.reverse.each do |k,v|
  puts "%-25s %3d" % [k,v.size]
end

