# -*- coding: binary -*-

require 'rex/proto/kerberos/keytab'
require 'rex/proto/kerberos/keytab/krb5_keytab'

RSpec.shared_examples_for 'a parseable keytab' do
  let(:expected) do
    described_class.new(
      {
        file_format_version: 0x502,
        key_entries: [
          {
            len: 84,
            count_of_components: 1,
            realm: 'DOMAIN.LOCAL',
            components: ['Administrator'],
            name_type: 1,
            timestamp: expected_timestamp,
            vno8: 1,
            keyblock: {
              enctype: 18,
              data: "\xC4\xA3\xF3\x1Dd\xAF\xA6H\xA6\xD0\x8D\avV>\x128\xB9v\xD0\xB9\x0Fy\xEA\a!\x946\x82\x94\xE9)"
            },
            vno: 1,
            flags: 0
          },
          {
            len: 68,
            count_of_components: 1,
            realm: 'DOMAIN.LOCAL',
            components: ['Administrator'],
            name_type: 1,
            timestamp: expected_timestamp,
            vno8: 1,
            keyblock: {
              enctype: 17,
              data: "\xBA\xBAC\xA8\xB9{\xAC\xA1S\xBDT\xB2\xF0wJ\xD7"
            },
            vno: 1,
            flags: 0
          },
          {
            len: 68,
            count_of_components: 1,
            realm: 'DOMAIN.LOCAL',
            components: ['Administrator'],
            name_type: 1,
            timestamp: expected_timestamp,
            vno8: 1,
            keyblock: {
              enctype: 23,
              data: "\x88F\xF7\xEA\xEE\x8F\xB1\x17\xAD\x06\xBD\xD80\xB7Xl"
            },
            vno: 1,
            flags: 0
          }
        ]
      }
    )
  end

  it 'parses the keytab string' do
    result = described_class.read(keytab)
    expect(result).to eq(expected)
    expect(result.key_entries.flat_map(&:principal)).to eq(%w[Administrator@DOMAIN.LOCAL Administrator@DOMAIN.LOCAL Administrator@DOMAIN.LOCAL])
  end
end

RSpec.describe Rex::Proto::Kerberos::Keytab::Krb5Keytab do
=begin
  Generated with heimdal ktutil; which has two additional bytes at the end for a 32-bit kvno and flags which are
  not present in the mit format

  rm -f heimdal.keytab
  ktutil --keytab=./heimdal.keytab --verbose add --password=password --principal=Administrator@DOMAIN.LOCAL --enctype=aes256-cts-hmac-sha1-96 --kvno=1
  ktutil --keytab=./heimdal.keytab --verbose add --password=password --principal=Administrator@DOMAIN.LOCAL --enctype=aes128-cts-hmac-sha1-96 --kvno=1
  ktutil --keytab=./heimdal.keytab --verbose add --password=password --principal=Administrator@DOMAIN.LOCAL --enctype=arcfour-hmac-md5 --kvno=1
  ktutil --keytab=./heimdal.keytab --verbose list

  ruby -r 'active_support/core_ext/array' -e 'puts File.binread("./heimdal.keytab").bytes.map { |x| "\\x#{x.to_s(16).rjust(2, "0")}" }.in_groups_of(16).map { |row| "\"#{row.join("")}\"" }.join(" \\ \n")'
=end
  let(:valid_heimdal_keytab) do
    "\x05\x02\x00\x00\x00\x54\x00\x01\x00\x0c\x44\x4f\x4d\x41\x49\x4e" \
    "\x2e\x4c\x4f\x43\x41\x4c\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74" \
    "\x72\x61\x74\x6f\x72\x00\x00\x00\x01\x63\x38\x7e\x21\x01\x00\x12" \
    "\x00\x20\xc4\xa3\xf3\x1d\x64\xaf\xa6\x48\xa6\xd0\x8d\x07\x76\x56" \
    "\x3e\x12\x38\xb9\x76\xd0\xb9\x0f\x79\xea\x07\x21\x94\x36\x82\x94" \
    "\xe9\x29\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x44\x00\x01" \
    "\x00\x0c\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x0d" \
    "\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x00\x00\x00" \
    "\x01\x63\x38\x7e\x21\x01\x00\x11\x00\x10\xba\xba\x43\xa8\xb9\x7b" \
    "\xac\xa1\x53\xbd\x54\xb2\xf0\x77\x4a\xd7\x00\x00\x00\x01\x00\x00" \
    "\x00\x00\x00\x00\x00\x44\x00\x01\x00\x0c\x44\x4f\x4d\x41\x49\x4e" \
    "\x2e\x4c\x4f\x43\x41\x4c\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74" \
    "\x72\x61\x74\x6f\x72\x00\x00\x00\x01\x63\x38\x7e\x21\x01\x00\x17" \
    "\x00\x10\x88\x46\xf7\xea\xee\x8f\xb1\x17\xad\x06\xbd\xd8\x30\xb7" \
    "\x58\x6c\x00\x00\x00\x01\x00\x00\x00\x00"
  end
  let(:valid_heimdal_keytab_timestamp) do
    Time.parse('2022-10-01 18:51:29 +0100')
  end

=begin
  Generated with mit ktutil; which does not have the two separate bytes at the end for a 32-bit kvno and flags that heimdal adds

  rm -f mit.keytab
  printf "%b" "addent -password -p Administrator@DOMAIN.LOCAL -k 1 -e aes256-cts-hmac-sha1-96\npassword\nwrite_kt mit.keytab" | ktutil
  printf "%b" "addent -password -p Administrator@DOMAIN.LOCAL -k 1 -e aes128-cts-hmac-sha1-96\npassword\nwrite_kt mit.keytab" | ktutil
  printf "%b" "addent -password -p Administrator@DOMAIN.LOCAL -k 1 -e arcfour-hmac-md5\npassword\nwrite_kt mit.keytab" | ktutil

  ruby -r 'active_support/core_ext/array' -e 'puts File.binread("./mit.keytab").bytes.map { |x| "\\x#{x.to_s(16).rjust(2, "0")}" }.in_groups_of(16).map { |row| "\"#{row.join("")}\"" }.join(" \\ \n")'
=end
  let(:valid_mit_keytab) do
    "\x05\x02\x00\x00\x00\x50\x00\x01\x00\x0c\x44\x4f\x4d\x41\x49\x4e" \
    "\x2e\x4c\x4f\x43\x41\x4c\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74" \
    "\x72\x61\x74\x6f\x72\x00\x00\x00\x01\x63\x38\x7e\x45\x01\x00\x12" \
    "\x00\x20\xc4\xa3\xf3\x1d\x64\xaf\xa6\x48\xa6\xd0\x8d\x07\x76\x56" \
    "\x3e\x12\x38\xb9\x76\xd0\xb9\x0f\x79\xea\x07\x21\x94\x36\x82\x94" \
    "\xe9\x29\x00\x00\x00\x01\x00\x00\x00\x40\x00\x01\x00\x0c\x44\x4f" \
    "\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x0d\x41\x64\x6d\x69" \
    "\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x00\x00\x00\x01\x63\x38\x7e" \
    "\x45\x01\x00\x11\x00\x10\xba\xba\x43\xa8\xb9\x7b\xac\xa1\x53\xbd" \
    "\x54\xb2\xf0\x77\x4a\xd7\x00\x00\x00\x01\x00\x00\x00\x40\x00\x01" \
    "\x00\x0c\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x0d" \
    "\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x00\x00\x00" \
    "\x01\x63\x38\x7e\x45\x01\x00\x17\x00\x10\x88\x46\xf7\xea\xee\x8f" \
    "\xb1\x17\xad\x06\xbd\xd8\x30\xb7\x58\x6c\x00\x00\x00\x01"
  end
  let(:valid_mit_keytab_timestamp) do
    Time.parse('2022-10-01 18:52:05 +0100')
  end

  describe '#read' do
    context 'with a heimdal keytab' do
      let(:keytab) { valid_heimdal_keytab }
      let(:expected_timestamp) { valid_heimdal_keytab_timestamp }

      it_behaves_like 'a parseable keytab'
    end

    context 'with an mit keytab' do
      let(:keytab) { valid_mit_keytab }
      let(:expected_timestamp) { valid_mit_keytab_timestamp }

      it_behaves_like 'a parseable keytab'
    end
  end

  describe '#to_binary_s' do
    context 'when a new keytab file is created without providing optional length fields' do
      let(:timestamp) { valid_heimdal_keytab_timestamp }
      it 'returns a serialized binary string' do
        data = {
          key_entries: [
            {
              realm: 'DOMAIN.LOCAL',
              components: ['Administrator'],
              name_type: 1,
              timestamp: timestamp,
              vno8: 1,
              keyblock: {
                enctype: 18,
                data: "\xC4\xA3\xF3\x1Dd\xAF\xA6H\xA6\xD0\x8D\avV>\x128\xB9v\xD0\xB9\x0Fy\xEA\a!\x946\x82\x94\xE9)"
              },
              vno: 1,
              flags: 0
            },
            {
              realm: 'DOMAIN.LOCAL',
              components: ['Administrator'],
              name_type: 1,
              timestamp: timestamp,
              vno8: 1,
              keyblock: {
                enctype: 17,
                data: "\xBA\xBAC\xA8\xB9{\xAC\xA1S\xBDT\xB2\xF0wJ\xD7"
              },
              vno: 1,
              flags: 0
            },
            {
              realm: 'DOMAIN.LOCAL',
              components: ['Administrator'],
              name_type: 1,
              timestamp: timestamp,
              vno8: 1,
              keyblock: {
                enctype: 23,
                data: "\x88F\xF7\xEA\xEE\x8F\xB1\x17\xAD\x06\xBD\xD80\xB7Xl"
              },
              vno: 1,
              flags: 0
            }
          ]
        }
        expect(described_class.new(data).to_binary_s).to eq(valid_heimdal_keytab)
      end
    end

    context 'when a heimdal keytab file is parsed and serialized again' do
      it 'returns the correct packed representation' do
        expect(described_class.read(valid_heimdal_keytab).to_binary_s).to eq(valid_heimdal_keytab)
      end
    end
  end
end
