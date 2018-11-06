#! /usr/bin/env ruby

# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++


# mresolv [ -d ] [ -n number ] [ -t timeout ] [ filename... ]
# 
# mresolv performs multiple DNS lookups in parallel.  Names to query
# are read from the list of files given on the command line, or from the
# standard input.
# 
# = OPTIONS
# 
# *-d : Turn on debugging output.
# 
# *-n number : Set the number of queries to have in progress at any time.
# 
# *-t timeout : Set the query timeout for each name in seconds.

# Examples for running:
#
# echo my-domain.com | ./mresolv.rb
# or
# ./mresolv.rb  # then type domain name(s) separated by new lines and then ctrl-D

require 'dnsruby'
require 'getoptLong'

opts = GetoptLong.new(
  ['-d', GetoptLong::NO_ARGUMENT],
  ['-n', GetoptLong::REQUIRED_ARGUMENT],
  ['-t', GetoptLong::REQUIRED_ARGUMENT])

max_outstanding = 32	# number of requests to have outstanding at any time
timeout = 15    # timeout (seconds)
debug = false
opts.each do |opt, arg|
  case opt
  when '-d'
    Dnsruby.log.level = Logger::INFO
    debug = true
  when '-n'
    max_outstanding = arg.to_i
  when '-t'
    timeout = arg
  end
end

resolver = Dnsruby::Resolver.new
resolver.query_timeout = timeout

# We want to have a rolling window of max_outstanding queries.
in_progress = 0

q = Queue.new
eof = false

until eof
  # Have the thread loop round, send queries until max_num are outstanding.
  while !eof && in_progress < max_outstanding
    print('DEBUG: reading...') if debug
    unless (name = gets)
      print("EOF.\n") if debug
      eof = true
      break
    end
    name.chomp!
    resolver.send_async(Dnsruby::Message.new(name), q, name)
    in_progress += 1
    print("name = #{name}, outstanding = #{in_progress}\n")   if debug
  end
  # Keep receiving while the query pool is full, or the list has been queried
  while in_progress >= max_outstanding || (eof && in_progress > 0)
    id, result, error = q.pop
    in_progress -= 1
    if error
      print("#{id}:\t#{error}\n")
    else
      print("#{result.answer.join("\n")}\n")
    end
  end
end
