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

class TestQuestion < Minitest::Test

  include Dnsruby

  def test_question
    domain = "example.com"
    type = Types.MX
    klass = Classes.IN

    q = Question.new(domain, type, klass)
    assert(q, "new() returned something")
    assert_equal(domain, q.qname.to_s, "qName()")
    assert_equal(type, q.qtype, "qType()")
    assert_equal(klass, q.qclass, "qClass()")

    # 
    #  Check the aliases
    # 
    assert_equal(q.zname.to_s,  domain, 'zName()'  );
    assert_equal(q.ztype,  type,   'zType()'  );
    assert_equal(q.zclass, klass,  'zClass()' );

    # 
    #  Check that we can change stuff
    # 
    q.qname=('example.net');
    q.qtype=('A');
    q.qclass=('CH');

    assert_equal('example.net', q.qname.to_s,  'qName()'  );
    assert_equal(q.qtype,  Types.A,           'qType()'  );
    assert_equal(q.qclass, Classes.CH,          'qClass()' );

  end
end
