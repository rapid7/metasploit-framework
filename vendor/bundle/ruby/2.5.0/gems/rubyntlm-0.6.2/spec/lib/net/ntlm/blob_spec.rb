require 'spec_helper'

describe Net::NTLM::Blob do

  fields = [
      { :name => :blob_signature, :class => Net::NTLM::Int32LE, :value => 257, :active => true },
      { :name => :reserved, :class => Net::NTLM::Int32LE, :value => 0, :active => true },
      { :name => :timestamp, :class => Net::NTLM::Int64LE, :value => 0, :active => true },
      { :name => :challenge, :class => Net::NTLM::String, :value => '', :active => true },
      { :name => :unknown1, :class => Net::NTLM::Int32LE, :value => 0, :active => true },
      { :name => :target_info, :class => Net::NTLM::String, :value => '', :active => true },
      { :name => :unknown2, :class => Net::NTLM::Int32LE, :value => 0, :active => true },
  ]

  it_behaves_like 'a fieldset', fields
end
