require 'ostruct'

RSpec.describe Msf::Trace::KerberosTicketTrace do
  let(:mod) do
    double('framework_module').tap do |m|
      allow(m).to receive(:print_line)
    end
  end

  let(:as_rep) do
    double('as_rep',
      crealm: 'TEST.LOCAL',
      cname: double(name_string: ['Administrator']),
      enc_part: double(etype: 23)
    )
  end

  let(:response) do
    OpenStruct.new(
      as_rep: as_rep,
      decrypted_part: nil
    )
  end

  describe '.print_metadata' do
    it 'prints kerberos metadata without crashing' do
      expect {
        described_class.print_metadata(response, mod)
      }.not_to raise_error
    end
  end

  describe '.print_full' do
    let(:decrypted_part) do
      double(
        starttime: Time.now,
        endtime: Time.now + 3600,
        flags: ['forwardable', 'renewable']
      )
    end

    let(:full_response) do
      OpenStruct.new(
        as_rep: as_rep,
        decrypted_part: decrypted_part
      )
    end

    it 'prints full kerberos details without crashing' do
      expect {
        described_class.print_full(full_response, mod)
      }.not_to raise_error
    end
  end
end
