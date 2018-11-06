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
module Dnsruby
  class RR
    # DNS SPF resource record

    # This is a clone of the TXT record. This class therfore completely inherits
    # all properties of the Dnsruby::Resource::TXT class.
    # 
    # Please see the Dnsruby::Resource::TXT documentation for details
    # RFC 1035 Section 3.3.14, draft-schlitt-ospf-classic-02.txt
    class SPF < TXT
      TypeValue = Types::SPF #:nodoc: all
    end
  end
end