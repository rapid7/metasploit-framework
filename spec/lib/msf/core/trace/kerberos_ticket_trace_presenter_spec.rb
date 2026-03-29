# frozen_string_literal: true

require 'spec_helper'
require 'ostruct'
require 'msf/core/trace/kerberos_ticket_trace_presenter'

RSpec.describe Msf::Trace::KerberosTicketTracePresenter do
  # ── Shared doubles ──────────────────────────────────────────────────────────

  let(:cname) { double('PrincipalName', name_string: ['Administrator']) }

  let(:enc_part) { double('EncPart', etype: 18, cipher: 'deadbeef') }

  let(:as_rep) do
    double('AsRep',
           crealm:   'CONTOSO.LOCAL',
           cname:    cname,
           enc_part: enc_part)
  end

  let(:dec_part) do
    double('DecryptedPart',
           starttime: Time.utc(2026, 6, 10, 9, 0, 0),
           endtime:   Time.utc(2026, 6, 10, 19, 0, 0),
           flags:     ['forwardable', 'renewable', 'pre-authent'],
           key:       'sessionkeyvalue')
  end

  let(:response) do
    OpenStruct.new(as_rep: as_rep, decrypted_part: dec_part)
  end

  let(:response_no_dec) do
    OpenStruct.new(as_rep: as_rep, decrypted_part: nil)
  end

  # ── #to_s_metadata ──────────────────────────────────────────────────────────
  describe '#to_s_metadata' do
    subject { described_class.new(response).to_s_metadata }

    it 'returns a string' do
      expect(subject).to be_a(String)
    end

    it 'includes the separator' do
      expect(subject).to include('[KerberosTrace]')
    end

    it 'includes realm and principal' do
      expect(subject).to include('CONTOSO.LOCAL')
      expect(subject).to include('Administrator')
    end

    it 'includes the encryption type' do
      expect(subject).to include('18')
    end

    it 'does not include timing or flags' do
      expect(subject).not_to match(/Start|End|Flags/)
    end

    it 'returns nil when response is nil' do
      expect(described_class.new(nil).to_s_metadata).to be_nil
    end

    it 'returns nil when as_rep is nil' do
      r = OpenStruct.new(as_rep: nil, decrypted_part: nil)
      expect(described_class.new(r).to_s_metadata).to be_nil
    end

    it 'falls back to unknown for nil enc_part' do
      rep = double('AsRep', crealm: 'TEST.LOCAL', cname: cname, enc_part: nil)
      r   = OpenStruct.new(as_rep: rep, decrypted_part: nil)
      expect(described_class.new(r).to_s_metadata).to include('unknown')
    end

    it 'falls back to unknown for nil cname' do
      rep = double('AsRep', crealm: 'TEST.LOCAL', cname: nil, enc_part: enc_part)
      r   = OpenStruct.new(as_rep: rep, decrypted_part: nil)
      expect(described_class.new(r).to_s_metadata).to include('unknown')
    end
  end

  # ── #to_s_full ───────────────────────────────────────────────────────────────
  describe '#to_s_full' do
    subject { described_class.new(response).to_s_full }

    it 'includes metadata fields' do
      expect(subject).to include('CONTOSO.LOCAL')
      expect(subject).to include('18')
    end

    it 'includes start time' do
      expect(subject).to include('Start')
    end

    it 'includes end time' do
      expect(subject).to include('End')
    end

    it 'includes flags joined as comma-separated string' do
      expect(subject).to include('forwardable')
    end

    it 'includes session key label and value in plain text (uncensored)' do
      expect(subject).to include('Session Key')
      expect(subject).to include('sessionkeyvalue')
    end

    it 'includes cipher text label and value in plain text (uncensored)' do
      expect(subject).to include('Cipher Text')
      expect(subject).to include('deadbeef')
    end

    it 'does not crash when enc_part is nil' do
      rep = double('AsRep', crealm: 'TEST.LOCAL', cname: cname, enc_part: nil)
      r   = OpenStruct.new(as_rep: rep, decrypted_part: dec_part)
      expect { described_class.new(r).to_s_full }.not_to raise_error
    end

    it 'returns only metadata when decrypted_part is nil (AS-REP roasting)' do
      result = described_class.new(response_no_dec).to_s_full
      expect(result).to include('CONTOSO.LOCAL')
      expect(result).not_to match(/Start|End|Flags/)
    end

    it 'handles flags that do not respond to join' do
      dec = double('DecPart',
                   starttime: Time.utc(2026, 6, 10, 9, 0, 0),
                   endtime:   Time.utc(2026, 6, 10, 19, 0, 0),
                   flags:     'forwardable',
                   key:       nil)
      r = OpenStruct.new(as_rep: as_rep, decrypted_part: dec)
      expect { described_class.new(r).to_s_full }.not_to raise_error
    end

    it 'returns nil when as_rep is nil' do
      r = OpenStruct.new(as_rep: nil, decrypted_part: nil)
      expect(described_class.new(r).to_s_full).to be_nil
    end
  end

  # ── #to_s_full_censored ──────────────────────────────────────────────────────
  describe '#to_s_full_censored' do
    subject { described_class.new(response).to_s_full_censored }

    it 'includes timing and flags' do
      expect(subject).to include('Start')
      expect(subject).to include('End')
      expect(subject).to include('forwardable')
    end

    it 'does not include session key' do
      expect(subject).not_to include('Session Key')
      expect(subject).not_to include('sessionkeyvalue')
    end

    it 'does not include cipher text' do
      expect(subject).not_to include('Cipher Text')
      expect(subject).not_to include('deadbeef')
    end

    it 'returns only metadata when decrypted_part is nil' do
      result = described_class.new(response_no_dec).to_s_full_censored
      expect(result).to include('CONTOSO.LOCAL')
      expect(result).not_to match(/Start|End|Flags/)
    end

    it 'returns nil when as_rep is nil' do
      r = OpenStruct.new(as_rep: nil, decrypted_part: nil)
      expect(described_class.new(r).to_s_full_censored).to be_nil
    end
  end
end
