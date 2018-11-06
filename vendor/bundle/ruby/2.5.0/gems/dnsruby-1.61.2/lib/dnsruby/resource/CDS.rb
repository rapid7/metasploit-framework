# --
# Copyright 2018 Caerketton Tech Ltd
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
    # RFC4034, section 4
    # The DS Resource Record refers to a DNSKEY RR and is used in the DNS
    # DNSKEY authentication process.  A DS RR refers to a DNSKEY RR by
    # storing the key tag, algorithm number, and a digest of the DNSKEY RR.
    # Note that while the digest should be sufficient to identify the
    # public key, storing the key tag and key algorithm helps make the
    # identification process more efficient.  By authenticating the DS
    # record, a resolver can authenticate the DNSKEY RR to which the DS
    # record points.  The key authentication process is described in
    # [RFC4035].

    class CDS < DS

      ClassValue = nil #:nodoc: all
      TypeValue = Types::CDS #:nodoc: all
    end
  end
end
