# --
# Copyright 2008 Nominet UK
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
     # RFC4431 specifies that the DLV is assigned type 32769, and the
     #  rdata is identical to that of the DS record.

     class DLV < RR::DS
       ClassValue = nil #:nodoc: all
       TypeValue = Types::DLV #:nodoc: all
     end
   end
end