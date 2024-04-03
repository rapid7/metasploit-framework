require 'rex/proto/ms_adts/key_credential'
require 'pry-byebug'

RSpec.describe Rex::Proto::MsAdts::KeyCredential do

  let(:credential_str) do
    ["00020000200001767b3c80129f41b40503d78436c1c2084c2b79dd81ac19" +
    "545eaa09a0b1448b41200002508e0ee3afa57294951857688e9a548d3a1f" +
    "bfc6f74c1df91f1bf6ef994ca1fe1b010352534131000800000300000000" +
    "0100000000000000000000010001edcb08aca75908258e2157dca5ef2679" +
    "90204502a4119482fa2eca16a4134d4a5dbf6eec9771732e1196ee490246" +
    "88dfbe51905343fb85a946b82e76a0e9b720d16c576f6b51a930ab69d134" +
    "48ac0f5a2722b00559eb25a8359f9b0d00fc52f9fc44f84d0dfb15d45d3c" +
    "af9c98ff7f0258867855916aa42d36042dc365717257be6f076cbc6ee282" +
    "14ab653860d18778fc45b9bb5c6f9b31d9b166a9000332d0c486f0d09a63" +
    "ffdd9e6d9cdbe89f6bd8c79b69d90d133d9eb8893999628bcddd107876c1" +
    "b025872ba6657ecf92b673e24ee4f6eabc52c0f5907ec4cf57627a12752e" +
    "587499893aae1bff5461f4d55e025d1ff7646baaf1b6500f6e2493174a79" +
    "010004010100050010000695c280f0bc6f290e4c8b6ad1d1b3545c020007" +
    "0100080008ecab5af7ce7fda01080009ecab5af7ce7fda01"].pack('H*')
  end
  let(:credential_struct) do
    raw = credential_str
    Rex::Proto::MsAdts::KeyCredentialStruct.read(raw)
  end

  it 'reads correctly' do
    expect(credential_struct).to be_a Rex::Proto::MsAdts::KeyCredentialStruct
    credential = Rex::Proto::MsAdts::KeyCredential.from_struct(credential_struct)
    result = credential.to_struct.to_binary_s
    expect(result).to eq credential_str
  end
end
