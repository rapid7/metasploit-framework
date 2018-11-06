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

class TestQueue < Minitest::Test
  def test_queue
    q = Queue.new
    r = Dnsruby::Resolver.new
#    Dnsruby::TheLog.level=Logger::DEBUG
    timeout = 15
    num_queries = 100
    r.query_timeout = timeout
    num_queries.times do |i|
      r.send_async(Dnsruby::Message.new("example.com"), q, i)
#      print "Sent #{i}\n"
    end
    sleep(timeout * 2)
    assert(q.size == num_queries, "#{num_queries} expected, but got #{q.size}")
  end
end
