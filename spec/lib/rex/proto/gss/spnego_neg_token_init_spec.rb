# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Gss::SpnegoNegTokenInit do
  let(:sample) do
    ['605a06062b0601050502a050304ea00e300c060a2b06010401823702020aa23c043a4e544c4d5353500001000000358288e20e000e00200000000b000b002e0000006b65726265726f732e6973737565574f524b53544154494f4e00'].pack('H*')
  end

  it 'Correctly parses a sample' do
    result = described_class.parse(sample)
    expect(result.mech_token).to start_with('NTLM')
    expect(result.mech_type_list[0].value).to eq("1.3.6.1.4.1.311.2.2.10")
    expect(result[:gssapi][:oid].value).to eq("1.3.6.1.5.5.2")
  end
end
