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

require_relative 'spec_helper'

class TestSoakBase # < Minitest::Test

  include Dnsruby

  Rrs = [
  {
    :type       => Types.A,
    :name       => 'ns1.google.com.',
    :address    => '10.0.1.128'
  },
  {
    :type       => Types::MX,
    :name       => 'ns1.google.com.',
    :exchange   => 'ns1.google.com.',
    :preference => 10
  },
  {
    :type       => 'CNAME',
    :name       => 'ns1.google.com.',
    :domainname => 'a.t.dnsruby.validation-test-servers.nominet.org.uk'
  },
  {
    :type       => Types.TXT,
    :name       => 'ns1.google.com.',
    :strings    => ['Net-DNS']
  }
  ]

  def TestSoakBase.test_continuous_queries_asynch_single_res
    #  Have two threads looping, with one sending, and one receiving queries.
    #  Never exceed more than 200 concurrent queries, but make sure they're always running.
    outstanding_limit = 1
    num_loops = 2000
    num_sent = 0
    q = Queue.new
    timed_out = 0
    mutex = Mutex.new
    start = Time.now
    num_in_progress = 0
    sender = Thread.new{
      res = SingleResolver.new
      res.packet_timeout=5
      num_loops.times do |i|
        rr_count = 0
        Rrs.each do |data|
          rr_count+=1
          while (mutex.synchronize{num_in_progress> outstanding_limit}) do
            sleep(0.01)
          end
          res.send_async(Message.new(data[:name], data[:type]), q, [i,rr_count])
          puts num_sent
          num_sent+=1
          mutex.synchronize {
            num_in_progress+=1
          }
        end
      end

    }
    receiver = Thread.new{
     (num_loops*4).times do |i|
        id,ret, error = q.pop
        mutex.synchronize {
          num_in_progress-=1
        }
        if (error.class == ResolvTimeout)
          timed_out+=1
          #         p "Number #{i} timed out!"
        elsif (ret.class != Message)
          Dnsruby.log.debug("tc_single_resolver : Query #{i} ERROR RETURNED : #{error.class}, #{error}")
        end
      end
    }
    sender.join
    receiver.join
    assert(num_in_progress==0)
    stop=Time.now
    time_taken=stop-start
    puts "Query count : #{num_sent}, #{timed_out} timed out. #{time_taken} time taken"
    assert(timed_out < num_sent * 0.1, "#{timed_out} of #{num_sent} timed out!")
  end

  def TestSoakBase.test_continuous_queries_asynch_resolver
    #  Have two threads looping, with one sending, and one receiving queries.
    #  Never exceed more than 250 concurrent queries, but make sure they're always running.
    num_loops = 1000
    num_sent = 0
    q = Queue.new
    timed_out = 0
    mutex = Mutex.new
    start = Time.now
    num_in_progress = 0
    sender = Thread.new{
      res = Resolver.new
      #  On windows, MAX_FILES is 256. This means that we have to limit
      #  this test while we're not using single sockets.
      #  We run four queries per iteration, so we're limited to 64 runs.
      num_loops.times do |i|
        while (mutex.synchronize{num_in_progress> 50}) do # One query has several sockets in Resolver
          sleep(0.01)
        end
        res.send_async(Message.new("example.com", Types.A), q, [i,1])
        num_sent+=1
        mutex.synchronize {
          num_in_progress+=1
        }
      end
    }
    error_count=0
    receiver = Thread.new{
     (num_loops).times do |i|
        id,ret, error = q.pop
        mutex.synchronize {
          num_in_progress-=1
        }
        if (error.class == ResolvTimeout)
          timed_out+=1
          #         p "Number #{i} timed out!"
        elsif (ret.class != Message)
          error_count+=1
          Dnsruby.log.error("tc_single_resolver : Query #{i} ERROR RETURNED : #{error.class}, #{error}")
        end
      end
    }
    sender.join
    receiver.join
    assert(num_in_progress==0)
    stop=Time.now
    time_taken=stop-start
    puts "Query count : #{num_sent}, #{timed_out} timed out, #{error_count} other errors. #{time_taken} time taken"
    assert(timed_out < num_sent * 0.1, "#{timed_out} of #{num_sent} timed out!")
    assert(error_count == 0)
  end
end
