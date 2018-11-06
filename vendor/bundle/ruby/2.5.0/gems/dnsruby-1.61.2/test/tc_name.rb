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

class TestName < Minitest::Test

  include Dnsruby

  def test_label_length
    Name::Label.set_max_length(Name::Label::MaxLabelLength) # Other tests may have changed this
    #  Test max label length = 63
    begin
      name = Name.create("a.b.12345678901234567890123456789012345678901234567890123456789012345.com")
      assert(false, "Label of more than max=63 allowed")
    rescue ResolvError
    end
  end

  def test_name_length
    #  Test max name length=255
    begin
      name = Name.create("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123.com")
      assert(false, "Name of length > 255 allowed")
    rescue ResolvError
    end
  end

  def test_absolute
    n = Name.create("example.com")
    assert(!n.absolute?)
    n = Name.create("example.com.")
    assert(n.absolute?)
  end

  def test_wild
    n = Name.create("example.com")
    assert(!n.wild?)
    n = Name.create("*.example.com.")
    assert(n.wild?)
  end

  def test_canonical_ordering
    names = []
    names.push(Name.create("example"))
    names.push(Name.create("a.example"))
    names.push(Name.create("yljkjljk.a.example"))
    names.push(Name.create("Z.a.example"))
    names.push(Name.create("zABC.a.EXAMPLE"))
    names.push(Name.create("z.example"))
    names.push(Name.create("\001.z.example"))
    names.push(Name.create("*.z.example"))
#    names.push(Name.create("\200.z.example"))
    names.push(Name.create(["c8"].pack("H*")+".z.example"))
    names.each_index {|i|
      if (i < (names.length() - 1))
        assert(names[i].canonically_before(names[i+1]))
        assert(!(names[i+1].canonically_before(names[i])))
      end
    }
    assert(Name.create("x.w.example").canonically_before(Name.create("z.w.example")))
    assert(Name.create("x.w.example").canonically_before(Name.create("a.z.w.example")))
  end

  def test_escapes
    n1 = Name.create("\\nall.all.")
    n2 = Name.create("nall.all.")
    assert(n1 == n2, n1.to_s)
  end
end
