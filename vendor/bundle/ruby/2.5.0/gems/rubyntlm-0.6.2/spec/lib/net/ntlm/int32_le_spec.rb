require 'spec_helper'

describe Net::NTLM::Int32LE do

  int_values = {
      :default     => 252716124,
      :default_hex => "\x5C\x24\x10\x0f",
      :alt         => 235938908,
      :alt_hex     => "\x5C\x24\x10\x0e",
      :small       => "\x0F\x00",
      :size        => 4,
      :bits        => 32
  }


  it_behaves_like 'a field', 252716124, false
  it_behaves_like 'an integer field', int_values

end