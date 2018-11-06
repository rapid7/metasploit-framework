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

require 'set'

module Dnsruby

class TestHash < Minitest::Test

  def test_types_hash
    object1 = Types.new(Types::NSEC3)
    object2 = Types.new(Types::NSEC3)
    assert(object1 == object2)
    assert(object1.hash == object2.hash, "Hashes differed: #{object1.hash} != #{object2.hash}")
  end

  def test_types_set
    object1 = Types.new(Types::NSEC3)
    object2 = Types.new(Types::NSEC3)
    assert(object1 == object2)
    set = Set.new([object1, object2])
    assert(set.size == 1, "Two equal objects should result in a set size of 1, but instead the size was #{set.size}.")
  end

end
end
