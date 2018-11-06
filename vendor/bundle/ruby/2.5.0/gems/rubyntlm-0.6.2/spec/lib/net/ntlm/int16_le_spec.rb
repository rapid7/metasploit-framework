require 'spec_helper'

describe Net::NTLM::Int16LE do

  int_values = {
    :default     => 15,
    :default_hex => "\x0F\x00",
    :alt         => 14,
    :alt_hex     => "\x0E\x00",
    :small       => "\x0F",
    :size        => 2,
    :bits        => 16
  }

  it_behaves_like 'a field', 15, false
  it_behaves_like 'an integer field', int_values

end