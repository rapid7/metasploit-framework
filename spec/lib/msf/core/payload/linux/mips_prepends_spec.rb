# -*- coding: binary -*-

require 'spec_helper'

# Covers the PrependSetresuid/PrependSetreuid/PrependSetuid options added for mips64, mipsbe,
# and mipsle in lib/msf/core/payload/linux/{mips64,mipsbe,mipsle}/prepends.rb. Before that change
# `prepends_order`/`prepends_map` were empty for all three, so the options did not exist; nothing
# exercised the raw setresuid/setreuid/setuid syscall stubs actually being prepended onto a
# payload.
RSpec.describe 'Linux MIPS payload prepend options', :content do
  # Calls a method defined on a Prepends module without going through Msf::Payload::Linux::Prepends#initialize,
  # which requires a real module `info` hash and framework option registration that these plain data
  # tables don't need.
  def call_prepends_method(prepends_module, method_name)
    prepends_module.instance_method(method_name).bind(Object.new).call
  end

  # mipsbe and mipsle each hand-type their own literal byte string for every prepend instead of one
  # being derived from the other, so nothing stops the two tables from silently drifting apart (e.g. a
  # future PrependSetresgid added to only one file, or a mistyped nibble in the second, hand-authored
  # copy). These specs pin down the invariant that every mipsle prepend must be the exact word-by-word
  # byte-reversal of the corresponding mipsbe prepend, so such a change fails here instead of only
  # corrupting opcodes on one endianness in the field.
  describe 'mipsbe/mipsle byte-table parity' do
    let(:mipsbe_prepends) { call_prepends_method(Msf::Payload::Linux::Mipsbe::Prepends, :prepends_map) }
    let(:mipsle_prepends) { call_prepends_method(Msf::Payload::Linux::Mipsle::Prepends, :prepends_map) }

    it 'defines the same set of prepend options for both endiannesses' do
      expect(mipsle_prepends.keys.sort).to eq(mipsbe_prepends.keys.sort)
    end

    it 'is the exact word-by-word byte-reversal of the mipsbe table for every prepend' do
      mipsbe_prepends.each do |name, be_bytes|
        # each MIPS instruction is a 4-byte word; mipsle should be mipsbe with the bytes of every
        # word reversed, but the word order itself unchanged.
        expected_le_bytes = be_bytes.bytes.each_slice(4).flat_map(&:reverse).pack('C*')

        # neither prepends.rb file declares `# -*- coding: binary -*-`, so their string literals
        # come back as UTF-8-tagged even though the bytes themselves aren't valid UTF-8; `#b` compares
        # on raw bytes so that pre-existing encoding quirk doesn't produce a false mismatch here.
        expect(mipsle_prepends.fetch(name).b).to eq(expected_le_bytes.b),
                                                 "mipsle '#{name}' is not the byte-reversal of mipsbe '#{name}'"
      end
    end
  end

  describe 'well-formed prepend byte tables' do
    {
      'mips64' => Msf::Payload::Linux::Mips64::Prepends,
      'mipsbe' => Msf::Payload::Linux::Mipsbe::Prepends,
      'mipsle' => Msf::Payload::Linux::Mipsle::Prepends
    }.each do |arch, prepends_module|
      context arch do
        let(:prepends_order) { call_prepends_method(prepends_module, :prepends_order) }
        let(:prepends_map) { call_prepends_method(prepends_module, :prepends_map) }

        it 'declares byte strings whose length is a multiple of the 4-byte MIPS instruction width' do
          prepends_map.each do |name, bytes|
            expect(bytes.bytesize % 4).to eq(0),
                                          "#{arch} '#{name}' prepend is #{bytes.bytesize} bytes, not a whole number of MIPS instructions"
          end
        end

        it 'declares exactly one prepends_map entry per prepends_order option' do
          expect(prepends_map.keys.sort).to eq(prepends_order.sort)
        end
      end
    end
  end

  # Confirms that turning the new options on (not just leaving them at their default `false`) actually
  # prepends the expected raw syscall stub onto a real, loaded payload module and doesn't blow up
  # generation - the gap the static checks above can't cover.
  describe 'exec payload generation with prepend options enabled' do
    include_context 'Msf::Simple::Framework#modules loading'

    %w[
      linux/mips64/exec
      linux/mipsbe/exec
      linux/mipsle/exec
    ].each do |reference_name|
      context reference_name do
        def build_payload(reference_name)
          load_and_create_module(
            ancestor_reference_names: ["singles/#{reference_name}"],
            module_type: 'payload',
            reference_name: reference_name
          )
        end

        # Goes through generate_simple (as msfvenom/PayloadGenerator do), not generate_complete
        # directly: generate_simple validates the module first, which is what normalizes the
        # Prepend* OptBool datastore values from their raw, always-truthy string default ('false')
        # into real booleans before apply_prepends reads them.
        def generate_raw(pinst, options = {})
          pinst.generate_simple('Format' => 'raw', 'Options' => options, 'Encoder' => nil, 'DisableNops' => true)
        end

        it 'grows by exactly the prepended bytes when each Prepend option is enabled individually' do
          baseline_size = generate_raw(build_payload(reference_name)).bytesize
          prepends_map = build_payload(reference_name).prepends_map

          build_payload(reference_name).prepends_order.each do |option_name|
            pinst = build_payload(reference_name)

            expected_size = baseline_size + prepends_map.fetch(option_name).bytesize
            expect(generate_raw(pinst, option_name => 'true').bytesize).to eq(expected_size),
                                                                           "enabling #{option_name} on #{reference_name} did not add exactly the expected prepend bytes"
          end
        end

        it 'stacks all prepend options together without error' do
          pinst = build_payload(reference_name)
          all_enabled = pinst.prepends_order.to_h { |option_name| [option_name, 'true'] }

          total_prepend_bytes = pinst.prepends_order.sum { |name| pinst.prepends_map.fetch(name).bytesize }
          baseline_size = generate_raw(build_payload(reference_name)).bytesize

          expect(generate_raw(pinst, all_enabled).bytesize).to eq(baseline_size + total_prepend_bytes)
        end
      end
    end
  end
end
