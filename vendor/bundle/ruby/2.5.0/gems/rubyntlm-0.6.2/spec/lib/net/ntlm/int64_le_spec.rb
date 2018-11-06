require 'spec_helper'

describe Net::NTLM::Int64LE do

  int_values = {
      :default     => 5294967295,
      :default_hex => [5294967295 & 0x00000000ffffffff, 5294967295 >> 32].pack("V2"),
      :alt         => 5294967294,
      :alt_hex     => [5294967294 & 0x00000000ffffffff, 5294967294 >> 32].pack("V2"),
      :small       => "\x5C\x24\x10\x0f",
      :size        => 8,
      :bits        => 64
  }


  it_behaves_like 'a field', 252716124, false
  it_behaves_like 'an integer field', int_values

end