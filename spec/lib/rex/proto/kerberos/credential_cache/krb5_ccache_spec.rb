require 'time'

RSpec.describe Rex::Proto::Kerberos::CredentialCache::Krb5Ccache do
  subject(:object) { described_class.new }

  it { is_expected.to respond_to :magic }
  it { is_expected.to respond_to :version }
  it { is_expected.to respond_to :header }
  it { is_expected.to respond_to :default_principal }
  it { is_expected.to respond_to :credentials }

  it 'is big endian' do
    # version 3 and 4 are always big endian
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'is a BinData::Record' do
    expect(object).to be_a BinData::Record
  end

  describe '#magic' do
    it 'is a Uint8' do
      expect(object.magic).to be_a BinData::Uint8
    end
  end

  describe '#header' do
    it 'is a Struct' do
      expect(object.header).to be_a BinData::Struct
    end
  end

  describe '#version' do
    it 'is a Uint8' do
      expect(object.version).to be_a BinData::Uint8
    end
  end

  describe '#default_principal' do
    it 'is a Krb5CCachePrincipal' do
      expect(object.default_principal).to be_a Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal
    end
  end

  it 'reads its own binary representation and outputs the same value' do
    value = described_class.new(
      default_principal: Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal.new,
      credentials: [
        Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredential.new
      ]
    )
    binary = value.to_binary_s
    expect(described_class.read(binary)).to eq(value)
  end

  it 'parses raw ccache v4 data' do
    raw = <<-RAWCCACHE.gsub(/\s/, '').scan(/../).map { |x| x.hex.chr }.join
      0504000c00010008000000010000000000000001000000010000000c4d53464c41422e4c4f43414c00000009736d63696e74797265000000
      01000000010000000c4d53464c41422e4c4f43414c00000009736d63696e7479726500000002000000020000000c4d53464c41422e4c4f43
      414c000000066b72627467740000000c4d53464c41422e4c4f43414c001200000020b62fe5bca15fbb659738c38749a705d2952e70ce677d
      cfcfe38428e0fd3e404462b35b7062b35b7062b3e81062bc95ee0040e1000000000003000200000004c0a8fa86000200000004c0a89f8000
      0200000004c0a87a0100000000000004fc618204f8308204f4a003020105a10e1b0c4d53464c41422e4c4f43414ca221301fa003020102a1
      1830161b066b72627467741b0c4d53464c41422e4c4f43414ca38204b8308204b4a003020112a103020102a28204a6048204a239f93916f9
      cecc4c522a7b922b04e1495a319a69a85130239ca002287ff847897a9f9b1083f8cad57203044fda588df903c6988a06937efd0ea2e5c79c
      d912ef60dd4276c4cc2691cc72b1d68ecb50b0621424c0b9a24119306c1b73427e62daf5f7e256e8d4af53ca0f59ca811d03674678a5f663
      3e924df6d9c0660aafe7ef8d53ec7fa2cb338eb1574e0d3e10a623bd8b8f7a58713b2d97a796b6046db3b1ecec5a0bbb301447f6d4655152
      d8d0756b6e88553a9e44476cfe8722dad039df7242a4095f442774cb6d47b6950607b8013bd2d0e5f38b7993a48ee06e9033606f725f188f
      4d191d127d9051f32ad6d90d155a8d8ce547b2a228f68e331666cb1b7cddac16b271dec00df298cc2c3a286c0d878ed923e6cad36d3f3420
      1b9ebcd01f694811c9649aed4957922d39705bb9b6491fa202e819132c050a60a51e1db95c06f6e5e82288fbbed31de3958ccf26600f2f47
      988b13ede16702644f467e448a5e3249de1e65bd2cccfe3974cd01fd6687fea436d2cdc070724dead0afeb61be26f1103c2578dce4928491
      1c3f0399064010c46b0393889335b7f6613f7ba2c2e7669547d323ee7b9cfd2ca0768ec1a0822f7f455a8f43c045931955963ba088aa6b9e
      3c469777342a8ebc690eb562b95e2ca38e21f2517d0da48f851894837298dc2b3361d779650c2a20adf85c140eedf4a7b655f1dd43e89a65
      d205a10590345e26f21a7d031f1262e6b40b39b12f2f6cc398c5d16757829b486bd3ea6ab5a8d7cbc336c49e1f6a0e3353729b547743a5da
      8adab0ff738687edcbc5ed008fc4124751bc087055dd7393461a747520e6e3ac88984eed6c50c00ecf2592f0e21e9846ec2c5501a34ac577
      4285ead400b360402eb48bcce617cd82ce3862d8462e4f6953c26c8b4ee139ebeba5cafba9e371d415454e52a4979791f93215d9fa552290
      823f9bc9bc7ac379205bc61f3cdbcd277770440c635df9c0d3f8b17cb0d37a536a14775333e076bb86acb95a5e52695921ec6fb6aece4064
      1ca7b5a34241936e0b2bd089ae0e10857d9d924ffd811a8c23b11f75e41a860de20f9815e79063c77f765562bec088582a25d49a61ab75da
      5aa7fdfb39376f44fa12de8f7f95d604268318bf2cb9600cef79c37c9f525d09b4d1d32719ac9738b09c663ba75796ce32bde2c86f238d3d
      b13c1ec9ab84b446a1bac9f1774888637a895f066f1346822f64534982e563395ef026a94ab518a5ff52cfd85e385c901db7522088e2abca
      753dca85936a8d9ce800a7354c3645ef219edb44ad3d9b62fded223854c366c01e080434db9760340f9616bdc16c55c034893d16f0739d23
      6ae94d151e24a7f0d9ce88c273024ab9d78126c1bd8fff0dd1e29f3cfe8c03b0aa1873742622c5c98151ca6bde13d10d5dbd7879ed3c7f6a
      067e5676b967ca5f62dde84a306ecfa432072974ffe214d8778830e125e2e452f1b0566135657a7a0d559f16633645ff1d052df97eb3ee63
      202219a6e2b97b5bb158dddb28ad5d3be1d736807b892f6992a251d2f49b06e93b5a77c9a4cf50181ac4fb2f85bc1d616213090c5002b9f2
      ac7b6e6a3e551844d401eaf5f35801f542517de1aed0e8d34dce85e40c5c56683077fcf09822c05d91e139d33172ee595e5645bc6792a5f0
      e87bfe99890000000000000001000000010000000c4d53464c41422e4c4f43414c00000009736d63696e7479726500000000000000030000
      000c582d4341434845434f4e463a000000156b7262355f6363616368655f636f6e665f646174610000000770615f74797065000000206b72
      627467742f4d53464c41422e4c4f43414c404d53464c41422e4c4f43414c0000000000000000000000000000000000000000000000000000
      000000000000000000000000013200000000
    RAWCCACHE

    read_ccache = described_class.read(raw)
    ccache = described_class.new({
      magic: 5,
      version: 4,
      header: {
        header_length: 12,
        header_fields: [
          {
            field_type: 1,
            field_length: 8,
            field_value: {
              seconds: 1,
              microseconds: 0
            }
          }
        ]
      },
      default_principal: {
        name_type: 1,
        count_of_components: 1,
        realm: 'MSFLAB.LOCAL',
        components: ['smcintyre']
      },
      credentials: [
        {
          client: {
            name_type: 1,
            count_of_components: 1,
            realm: 'MSFLAB.LOCAL',
            components: ['smcintyre']
          },
          server: {
            name_type: 2,
            count_of_components: 2,
            realm: 'MSFLAB.LOCAL',
            components: ['krbtgt', 'MSFLAB.LOCAL']
          },
          keyblock: {
            enctype: 18,
            data: "\xB6/\xE5\xBC\xA1_\xBBe\x978\xC3\x87I\xA7\x05\xD2\x95.p\xCEg}\xCF\xCF\xE3\x84(\xE0\xFD>@D".b
          },
          authtime: Time.parse('2022-06-22 14:12:00 -0400'),
          starttime: Time.parse('2022-06-22 14:12:00 -0400'),
          endtime: Time.parse('2022-06-23 00:12:00 -0400'),
          renew_till: Time.parse('2022-06-29 14:11:58 -0400'),
          is_skey: false,
          ticket_flags: 1088487424,
          address_count: 3,
          addresses: [
            { addrtype: 2, data: IPAddr.new('192.168.250.134') },
            { addrtype: 2, data: IPAddr.new('192.168.159.128') },
            { addrtype: 2, data: IPAddr.new('192.168.122.1') }
          ],
          authdata_count: 0,
          authdatas: [],
          ticket: <<-RAWTICKET.gsub(/\s/, '').scan(/../).map { |x| x.hex.chr }.join,
          618204f8308204f4a003020105a10e1b0c4d53464c41422e4c4f43414ca221301fa003020102a11830161b066b72627467741b0c4d5346
          4c41422e4c4f43414ca38204b8308204b4a003020112a103020102a28204a6048204a239f93916f9cecc4c522a7b922b04e1495a319a69
          a85130239ca002287ff847897a9f9b1083f8cad57203044fda588df903c6988a06937efd0ea2e5c79cd912ef60dd4276c4cc2691cc72b1
          d68ecb50b0621424c0b9a24119306c1b73427e62daf5f7e256e8d4af53ca0f59ca811d03674678a5f6633e924df6d9c0660aafe7ef8d53
          ec7fa2cb338eb1574e0d3e10a623bd8b8f7a58713b2d97a796b6046db3b1ecec5a0bbb301447f6d4655152d8d0756b6e88553a9e44476c
          fe8722dad039df7242a4095f442774cb6d47b6950607b8013bd2d0e5f38b7993a48ee06e9033606f725f188f4d191d127d9051f32ad6d9
          0d155a8d8ce547b2a228f68e331666cb1b7cddac16b271dec00df298cc2c3a286c0d878ed923e6cad36d3f34201b9ebcd01f694811c964
          9aed4957922d39705bb9b6491fa202e819132c050a60a51e1db95c06f6e5e82288fbbed31de3958ccf26600f2f47988b13ede16702644f
          467e448a5e3249de1e65bd2cccfe3974cd01fd6687fea436d2cdc070724dead0afeb61be26f1103c2578dce49284911c3f0399064010c4
          6b0393889335b7f6613f7ba2c2e7669547d323ee7b9cfd2ca0768ec1a0822f7f455a8f43c045931955963ba088aa6b9e3c469777342a8e
          bc690eb562b95e2ca38e21f2517d0da48f851894837298dc2b3361d779650c2a20adf85c140eedf4a7b655f1dd43e89a65d205a1059034
          5e26f21a7d031f1262e6b40b39b12f2f6cc398c5d16757829b486bd3ea6ab5a8d7cbc336c49e1f6a0e3353729b547743a5da8adab0ff73
          8687edcbc5ed008fc4124751bc087055dd7393461a747520e6e3ac88984eed6c50c00ecf2592f0e21e9846ec2c5501a34ac5774285ead4
          00b360402eb48bcce617cd82ce3862d8462e4f6953c26c8b4ee139ebeba5cafba9e371d415454e52a4979791f93215d9fa552290823f9b
          c9bc7ac379205bc61f3cdbcd277770440c635df9c0d3f8b17cb0d37a536a14775333e076bb86acb95a5e52695921ec6fb6aece40641ca7
          b5a34241936e0b2bd089ae0e10857d9d924ffd811a8c23b11f75e41a860de20f9815e79063c77f765562bec088582a25d49a61ab75da5a
          a7fdfb39376f44fa12de8f7f95d604268318bf2cb9600cef79c37c9f525d09b4d1d32719ac9738b09c663ba75796ce32bde2c86f238d3d
          b13c1ec9ab84b446a1bac9f1774888637a895f066f1346822f64534982e563395ef026a94ab518a5ff52cfd85e385c901db7522088e2ab
          ca753dca85936a8d9ce800a7354c3645ef219edb44ad3d9b62fded223854c366c01e080434db9760340f9616bdc16c55c034893d16f073
          9d236ae94d151e24a7f0d9ce88c273024ab9d78126c1bd8fff0dd1e29f3cfe8c03b0aa1873742622c5c98151ca6bde13d10d5dbd7879ed
          3c7f6a067e5676b967ca5f62dde84a306ecfa432072974ffe214d8778830e125e2e452f1b0566135657a7a0d559f16633645ff1d052df9
          7eb3ee63202219a6e2b97b5bb158dddb28ad5d3be1d736807b892f6992a251d2f49b06e93b5a77c9a4cf50181ac4fb2f85bc1d61621309
          0c5002b9f2ac7b6e6a3e551844d401eaf5f35801f542517de1aed0e8d34dce85e40c5c56683077fcf09822c05d91e139d33172ee595e56
          45bc6792a5f0e87bfe9989
          RAWTICKET
          second_ticket: ''
        },
        {
          client: {
            name_type: 1,
            count_of_components: 1,
            realm: 'MSFLAB.LOCAL',
            components: ['smcintyre']
          },
          server: {
            name_type: 0,
            count_of_components: 3,
            realm: 'X-CACHECONF:',
            components: ['krb5_ccache_conf_data', 'pa_type', 'krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL']
          },
          keyblock: { enctype: 0, data: '' },
          authtime: Time.parse('1969-12-31 19:00:00 -0500'),
          starttime: Time.parse('1969-12-31 19:00:00 -0500'),
          endtime: Time.parse('1969-12-31 19:00:00 -0500'),
          renew_till: Time.parse('1969-12-31 19:00:00 -0500'),
          is_skey: false,
          ticket_flags: 0,
          address_count: 0,
          addresses: [],
          authdata_count: 0,
          authdatas: [],
          ticket: '2',
          second_ticket: ''
        }
      ]
    })
    expect(read_ccache).to eq ccache
  end
end
