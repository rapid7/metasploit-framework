require 'spec_helper'

describe Net::NTLM::Message::Type0 do

  fields = [
      { :name => :sign, :class => Net::NTLM::String, :value => Net::NTLM::SSP_SIGN, :active => true },
      { :name => :type, :class => Net::NTLM::Int32LE, :value => 0, :active => true },
  ]
  flags = [
      :UNICODE,
      :OEM,
      :REQUEST_TARGET,
      :NTLM,
      :ALWAYS_SIGN,
      :NTLM2_KEY
  ]
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags


end