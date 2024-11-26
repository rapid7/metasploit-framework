# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Gss::SpnegoNegTokenTarg do
  let(:sample) do
    ['a181b73081b4a0030a0100a10b06092a864882f712010202a2819f04819c60819906092a864886f71201020202006f8189308186a003020105a10302010fa27a3078a003020112a271046f3985e7ea1a4c6c0712edc09b17299b73e9fbb4aa516b55c55893820ea6399d4f25a6ba67ebfefef1ac66bdb78ae4896c21316b5d22b0b43f53b9984463f49d35f0fd89b1e1efa65887c0fdc03540a274fbe5c11e2551edbac5555720082329b5fda2b47c159ffefe25a50e4206c8fc'].pack('H*')
  end

  it 'Correctly parses a sample' do
    result = described_class.parse(sample)
    expect(result.neg_result).to eq(described_class::ACCEPT_COMPLETED)
    expect(result.supported_mech).to eq(Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value)
    expect(result.response_token.length).to eq(156)
    expect(result.mech_list_mic).to eq(nil)
  end
end
