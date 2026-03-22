# frozen_string_literal: true

require 'spec_helper'
require 'ostruct'
require 'msf/core/trace/kerberos_ticket_trace'

RSpec.describe Msf::Trace::KerberosTicketTrace do
  # ── Shared doubles ──────────────────────────────────────────────────────────
  # Use a real OpenStruct for the response so nil-safe accessor chains
  # (response&.as_rep, enc_part&.etype, cname&.name_string&.join) behave
  # exactly as they would against live Kerberos model objects.

  let(:mod) { instance_double('Msf::Module', print_line: nil) }

  let(:cname) do
    double('PrincipalName', name_string: ['Administrator'])
  end

  let(:as_rep) do
    double('AsRep',
      crealm:   'CONTOSO.LOCAL',
      cname:    cname,
      enc_part: double('EncPart', etype: 18)
    )
  end

  let(:dec_part) do
    double('DecryptedPart',
      starttime: Time.utc(2026, 6, 10, 9, 0, 0),
      endtime:   Time.utc(2026, 6, 10, 19, 0, 0),
      flags:     ['forwardable', 'renewable', 'pre-authent']
    )
  end

  let(:response) do
    OpenStruct.new(
      as_rep:         as_rep,
      decrypted_part: dec_part
    )
  end

  let(:response_no_dec) do
    OpenStruct.new(
      as_rep:         as_rep,
      decrypted_part: nil
    )
  end

  let(:nil_response) { nil }

  # ── print_metadata() ────────────────────────────────────────────────────────
  describe '.print_metadata' do
    it 'prints the separator line' do
      allow(mod).to receive(:print_line)
      expect(mod).to receive(:print_line).with(/KerberosTrace/)
      described_class.print_metadata(response, mod)
    end

    it 'prints the principal with realm and name_string joined' do
      allow(mod).to receive(:print_line)
      expect(mod).to receive(:print_line).with(/CONTOSO\.LOCAL/)
      expect(mod).to receive(:print_line).with(/Administrator/)
      described_class.print_metadata(response, mod)
    end

    it 'prints the encryption type' do
      allow(mod).to receive(:print_line)
      expect(mod).to receive(:print_line).with(/18/)
      described_class.print_metadata(response, mod)
    end

    it 'does not print timestamps or flags' do
      lines = []
      allow(mod).to receive(:print_line) { |l| lines << l }
      described_class.print_metadata(response, mod)
      expect(lines.join).not_to match(/Start|End|Flags/)
    end

    it 'returns safely when response is nil' do
      expect { described_class.print_metadata(nil_response, mod) }.not_to raise_error
    end

    it 'returns safely when as_rep is nil' do
      bad_response = OpenStruct.new(as_rep: nil, decrypted_part: nil)
      expect { described_class.print_metadata(bad_response, mod) }.not_to raise_error
    end

    it 'handles nil enc_part gracefully' do
      rep_no_enc = double('AsRep',
        crealm:   'CONTOSO.LOCAL',
        cname:    cname,
        enc_part: nil
      )
      r = OpenStruct.new(as_rep: rep_no_enc, decrypted_part: nil)
      allow(mod).to receive(:print_line)
      expect { described_class.print_metadata(r, mod) }.not_to raise_error
    end

    it 'handles nil cname gracefully' do
      rep_no_cname = double('AsRep',
        crealm:   'CONTOSO.LOCAL',
        cname:    nil,
        enc_part: double('EncPart', etype: 17)
      )
      r = OpenStruct.new(as_rep: rep_no_cname, decrypted_part: nil)
      allow(mod).to receive(:print_line)
      expect { described_class.print_metadata(r, mod) }.not_to raise_error
    end
  end

  # ── print_full() ────────────────────────────────────────────────────────────
  describe '.print_full' do
    it 'includes everything print_metadata prints' do
      allow(mod).to receive(:print_line)
      expect(mod).to receive(:print_line).with(/CONTOSO\.LOCAL/)
      expect(mod).to receive(:print_line).with(/18/)
      described_class.print_full(response, mod)
    end

    it 'prints the start time' do
      allow(mod).to receive(:print_line)
      expect(mod).to receive(:print_line).with(/Start/)
      described_class.print_full(response, mod)
    end

    it 'prints the end time' do
      allow(mod).to receive(:print_line)
      expect(mod).to receive(:print_line).with(/End/)
      described_class.print_full(response, mod)
    end

    it 'prints flags joined as a comma-separated string' do
      allow(mod).to receive(:print_line)
      expect(mod).to receive(:print_line).with(/forwardable/)
      described_class.print_full(response, mod)
    end

    it 'returns safely when decrypted_part is nil (AS-REP roasting)' do
      allow(mod).to receive(:print_line)
      expect { described_class.print_full(response_no_dec, mod) }.not_to raise_error
    end

    it 'still prints metadata when decrypted_part is nil' do
      lines = []
      allow(mod).to receive(:print_line) { |l| lines << l }
      described_class.print_full(response_no_dec, mod)
      expect(lines.join).to match(/CONTOSO\.LOCAL/)
    end

    it 'does not print timestamps when decrypted_part is nil' do
      lines = []
      allow(mod).to receive(:print_line) { |l| lines << l }
      described_class.print_full(response_no_dec, mod)
      expect(lines.join).not_to match(/Start|End|Flags/)
    end

    it 'handles flags that do not respond to join' do
      dec_no_join = double('DecryptedPart',
        starttime: Time.utc(2026, 6, 10, 9, 0, 0),
        endtime:   Time.utc(2026, 6, 10, 19, 0, 0),
        flags:     'forwardable'
      )
      r = OpenStruct.new(as_rep: as_rep, decrypted_part: dec_no_join)
      allow(mod).to receive(:print_line)
      expect { described_class.print_full(r, mod) }.not_to raise_error
    end

    it 'returns safely when response is nil' do
      expect { described_class.print_full(nil_response, mod) }.not_to raise_error
    end
  end
end
