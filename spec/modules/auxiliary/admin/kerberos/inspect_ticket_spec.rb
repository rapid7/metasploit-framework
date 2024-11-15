require 'rspec'

RSpec.shared_examples 'inspect ticket' do
  describe '#run' do
    context 'with no decryption key' do
      it 'displays the encrypted ticket' do
        subject.run
        expect(@output.join("\n")).to eq expected_encrypted_output
      end
    end

    context 'with the correct decryption key' do
      it 'displays the decrypted ticket' do
        subject.datastore[key_type] = key
        subject.run

        expect(@output.join("\n")).to eq expected_decrypted_output
      end
    end

    context 'with invalid key' do
      it 'warns the user the key is invalid' do
        subject.datastore[key_type] = invalid_key

        expect { subject.run }.to raise_error Msf::Auxiliary::Failed, invalid_key_error_msg
      end
    end

    context 'with both keys set' do
      it 'warns the user both keys may not be set' do
        subject.datastore['AES_KEY'] = aes_key
        subject.datastore['NTHASH'] = nthash
        error_msg = 'bad-config: NTHASH and AES_KEY may not both be set for inspecting a ticket'

        expect { subject.run }.to raise_error Msf::Auxiliary::Failed, error_msg
      end
    end
  end
end

RSpec.describe 'kerberos inspect ticket' do
  include_context 'Msf::UIDriver'
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'admin/kerberos/inspect_ticket'
    )
  end

  before(:each) do
    subject.datastore['VERBOSE'] = false
    subject.datastore['AES_KEY'] = nil
    subject.datastore['NTHASH'] = nil
    subject.datastore['TICKET_PATH'] = ticket_path
    allow(driver).to receive(:input).and_return(driver_input)
    allow(driver).to receive(:output).and_return(driver_output)
    subject.init_ui(driver_input, driver_output)
  end

  let(:aes_key) { '4b912be0366a6f37f4a7d571bee18b1173d93195ef76f8d1e3e81ef6172ab326' }
  let(:nthash) { '88E4D9FABAECF3DEC18DD80905521B29' }
  let(:invalid_key) { 'invalid_key' }

  let(:ccache_aes) do
    # msf6 auxiliary(admin/kerberos/forge_ticket) > options
    #
    # Module options (auxiliary/admin/kerberos/forge_ticket):
    #
    #    Name        Current Setting                                                   Required  Description
    #    ----        ---------------                                                   --------  -----------
    #    AES_KEY     4b912be0366a6f37f4a7d571bee18b1173d93195ef76f8d1e3e81ef6172ab326  no        The krbtgt/service AES key
    #    DOMAIN      windomain.local                                                   yes       The Domain (upper case) Ex: DEMO.LOCAL
    #    DOMAIN_SID  S-1-5-21-3541430928-2051711210-1391384369                         yes       The Domain SID, Ex: S-1-5-21-1755879683-3641577184-3486455962
    #    DURATION    3650                                                              yes       Duration of the ticket in days
    #    NTHASH                                                                        no        The krbtgt/service nthash
    #    SPN         cifs/dc.windomain.local                                           no        The Service Principal Name (Only used for silver ticket)
    #    USER        Administrator                                                     yes       The Domain User
    #    USER_RID    500                                                               yes       The Domain User's relative identifier(RID)
    #
    #
    # View the full module info with the info, or info -d command.
    #
    # msf6 auxiliary(admin/kerberos/forge_ticket) > forge_silver
    #
    # [*] [2023.01.13-14:31:25] TGS MIT Credential Cache ticket saved to /Users/dwelch/.msf4/loot/20230113143125_default_unknown_mit.kerberos.cca_398641.bin
    # [*] Auxiliary module execution completed
    # msf6 auxiliary(admin/kerberos/forge_ticket) >

    "\x05\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0f" \
    "\x57\x49\x4e\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00" \
    "\x00\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72" \
    "\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0f\x57\x49\x4e\x44" \
    "\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x00\x00\x0d\x41" \
    "\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x00\x00\x00\x01" \
    "\x00\x00\x00\x02\x00\x00\x00\x0f\x57\x49\x4e\x44\x4f\x4d\x41\x49" \
    "\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x00\x00\x04\x63\x69\x66\x73\x00" \
    "\x00\x00\x12\x64\x63\x2e\x77\x69\x6e\x64\x6f\x6d\x61\x69\x6e\x2e" \
    "\x6c\x6f\x63\x61\x6c\x00\x12\x00\x00\x00\x20\x30\x31\x36\x30\x31" \
    "\x30\x31\x30\x37\x65\x65\x30\x64\x36\x38\x38\x63\x39\x39\x61\x39" \
    "\x33\x38\x38\x36\x33\x34\x61\x65\x30\x34\x31\x63\xc1\x6b\x3d\x63" \
    "\xc1\x6b\x3d\x76\x8d\x6e\x3d\x76\x8d\x6e\x3d\x00\x50\xa0\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xd2\x61\x82\x03\xce" \
    "\x30\x82\x03\xca\xa0\x03\x02\x01\x05\xa1\x11\x1b\x0f\x57\x49\x4e" \
    "\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa2\x25\x30\x23" \
    "\xa0\x03\x02\x01\x01\xa1\x1c\x30\x1a\x1b\x04\x63\x69\x66\x73\x1b" \
    "\x12\x64\x63\x2e\x77\x69\x6e\x64\x6f\x6d\x61\x69\x6e\x2e\x6c\x6f" \
    "\x63\x61\x6c\xa3\x82\x03\x87\x30\x82\x03\x83\xa0\x03\x02\x01\x12" \
    "\xa1\x03\x02\x01\x02\xa2\x82\x03\x75\x04\x82\x03\x71\xec\x7a\xb2" \
    "\xbf\x57\x69\x55\x02\x0e\x1f\xf3\xeb\xdb\x0e\x37\x42\x67\x48\x62" \
    "\xbb\x63\x40\x9b\xc9\x70\x73\x03\x46\x8c\xdc\x4f\x4c\xcf\x8e\x66" \
    "\xf1\xd7\xad\x07\x68\x00\x5d\xec\xea\xe8\x0b\x79\x9c\x2e\x18\xac" \
    "\x40\x92\x0c\xf0\xcf\xdd\xaf\x4b\x9f\xf3\x3f\xcf\x59\x2e\xb3\x7b" \
    "\x99\x74\x80\x57\x8f\x74\xf2\xa1\xe6\xfc\x08\x60\x74\x30\xd2\x0b" \
    "\x7f\xfd\xd1\x4c\xa5\x1f\xb5\xd5\xe1\xfe\xa8\x62\xca\x5b\xf2\xad" \
    "\xd0\xbd\x1f\x2f\x8b\x60\xe0\xa6\x0a\xc7\xe7\xff\x08\xae\xb9\x2b" \
    "\xcd\xa9\x4a\xee\xd0\x68\x53\xa3\xed\xc4\xa0\x75\x3b\xc8\x0e\x6c" \
    "\x47\x90\x38\x92\xe7\x37\xa6\x27\xa4\x2e\xd6\x54\xa4\x9c\x30\xd6" \
    "\xf5\xea\x33\x68\x1c\x26\xea\x7e\xf8\x80\xe9\x94\x52\x2c\x68\xef" \
    "\x8f\x98\x6a\x32\xd1\xa2\x37\xd5\x44\xf5\x80\x64\x9b\x22\xe8\xb9" \
    "\x20\x4b\xf7\x00\x49\xbe\xab\x6f\xcb\x19\x59\x23\x80\xad\x86\x33" \
    "\xeb\x52\x0d\xbb\xf8\xf1\x9d\xd9\x7e\xfc\xf6\x88\x66\x24\x5d\xf0" \
    "\x40\xbf\x0e\x91\x17\x8b\x9e\x62\x34\xa5\x6e\x7d\x43\x7e\xcc\x4e" \
    "\xbf\x66\xab\x8b\xd0\xb1\x44\xa1\x7b\xe1\x89\x78\x38\xe3\xe1\x48" \
    "\x70\x4d\x1f\xfe\xc4\xb0\x5b\x70\x56\x66\xc2\x8f\x5e\x56\x3e\x2f" \
    "\x18\x95\x4b\x4c\x5a\x70\x06\x0b\xf6\x34\x7a\x2a\x27\x81\xa0\x96" \
    "\xc2\x06\x46\x29\x39\x38\xd9\x60\x56\xd3\x9d\x7f\x2a\x43\x66\x57" \
    "\xec\x93\x46\x19\x84\x16\x25\xd8\xc9\xa9\x37\xd8\xe5\xe1\xdd\x65" \
    "\x07\xc7\x35\xc3\x20\x10\x7a\x43\xf3\x71\x1f\x33\xdd\x1b\xd9\xac" \
    "\xb2\x85\xd7\x4f\xd0\x95\x1e\x76\x51\x47\x27\xa5\x4e\xf2\x23\x8a" \
    "\xbe\xae\xbd\x66\xbe\xeb\xca\x62\x49\x2b\x4e\xce\xa4\x1f\xfb\x89" \
    "\x0a\xe5\xa9\x8b\xfa\xd8\x6b\x12\x4d\x0b\xd3\x4e\xc9\x17\x49\x33" \
    "\xc1\xec\x1a\xa4\x99\xfa\xc3\xc1\x81\x82\x71\x07\x34\xe5\x6b\x87" \
    "\x88\x17\xce\x79\xa8\xb6\xbc\x70\x46\x4a\xc9\xcd\x7d\x93\xd8\xb5" \
    "\x69\x79\xa0\x89\x3c\x9e\xaa\xf2\x1d\x68\xb1\x63\xd0\xfb\x81\xff" \
    "\x1e\x77\xb7\xc9\x98\xaf\xe6\xe0\x02\xda\xd7\x88\x4f\xa7\xc6\x31" \
    "\xb1\x39\x65\xb4\x80\x36\x2a\x12\x08\xbb\x1e\xba\xd8\xcb\x97\x70" \
    "\xeb\xcc\x9b\x32\xfa\x4b\xd4\xa9\x50\x5d\x6a\xe2\x0f\x02\xa9\xd1" \
    "\x03\x59\x40\x4f\x79\xe7\x09\xf3\x6d\x57\x10\xfe\xff\x56\xff\xc1" \
    "\x4c\xb8\x47\xc1\x33\x1b\xc5\x84\x89\xbf\xc5\x60\x23\x1d\x62\xdc" \
    "\x07\x34\x24\x51\x6c\x60\x55\x3b\x30\xe3\x26\x7c\xcc\x73\x50\xee" \
    "\x27\xe8\xd4\xad\x1a\x9b\xfe\xb1\x66\xb5\xb6\x41\xc9\x9b\x1c\x33" \
    "\x17\x09\x38\x47\xf1\x2f\x9c\xdd\xbe\xc4\x0b\x61\x14\xf0\xbd\xe0" \
    "\xc3\xc2\x8c\x3e\x2b\x06\xe0\xf2\x74\x2e\xc1\x74\x19\x7c\x4c\xe8" \
    "\xf5\x45\x69\x40\xdd\xfb\xab\x0f\x8c\x0e\x21\x35\xcf\xc4\x73\x82" \
    "\x47\x47\xe1\xb8\x82\x3d\x87\x02\x5c\xb1\x47\xee\x51\x15\xda\xa6" \
    "\x92\xa8\x3e\x5b\x38\x61\x93\x6c\x87\x03\xe8\x68\x78\x19\x1d\xec" \
    "\x61\xe1\x03\x07\x98\xdd\xf7\xbc\x6e\x1f\x73\x79\xad\xb0\x4d\x99" \
    "\x39\x6d\xfa\xd6\xc2\x29\x4f\xa6\x4e\x60\x4a\x35\x09\x17\x1d\x9d" \
    "\x75\xaa\x5b\x27\x24\xec\xb0\x82\xee\x94\xe0\xb7\xdf\xbc\xc6\x16" \
    "\xf9\x11\x86\xe2\x09\xd3\xe6\x1b\x11\x57\x85\x22\x5e\x17\x71\x8f" \
    "\x7b\x25\xde\xbb\x03\x67\x05\xde\x3e\x24\x9f\x02\xe6\xab\xc3\xf8" \
    "\x3f\x3d\x0e\x64\x5b\x0a\xa3\xfe\x1c\x3c\x47\xb1\xce\x45\x3e\x83" \
    "\x71\xde\xd6\x6f\x35\xa7\xe1\x31\x5b\x65\x46\x58\x2d\xf0\xca\xc7" \
    "\x85\x0d\x42\x40\x09\xe0\x83\x8a\x86\x2c\xc4\xfc\xa8\x3d\x51\xc3" \
    "\x72\x00\x1d\x72\xe1\x65\x31\xe3\xf4\xd6\xe0\x37\x0a\x48\x24\xa5" \
    "\x02\xcc\x96\x9d\x9a\x81\x9e\xd9\xc6\x6c\x2d\xb2\x09\xac\x34\x17" \
    "\x57\xa8\x80\x89\x63\xfc\x03\xf7\xb6\x3c\x9f\x38\x95\xf0\x72\xff" \
    "\x4d\x79\xf0\x6e\x1f\x98\x20\x2f\x5d\xd2\xc9\xd1\xaa\x20\x35\xac" \
    "\x92\x5e\x62\x20\x29\x3d\xdf\xb1\x1b\xbd\x91\x40\x69\xae\xdf\xa6" \
    "\x78\x00\xbe\xcb\x26\xd7\x7a\xd4\xcf\x31\x55\xa8\xc4\x5d\xfa\x27" \
    "\xf5\x44\xc0\x2b\xb4\x94\x66\x78\xd6\xaa\x66\x6c\x05\xa4\x99\x3c" \
    "\x77\xdf\xd0\x26\x47\xb4\x40\x90\xae\x8a\x96\x02\xe0\xf3\x22\xf0" \
    "\x8d\xbb\x0d\x86\x5b\x0a\x7d\x7a\xee\x38\x45\xd3\x01\x46\x00\x00" \
    "\x00\x00"
  end

  let(:ccache_nthash) do
    # msf6 auxiliary(admin/kerberos/forge_ticket) > options
    #
    # Module options (auxiliary/admin/kerberos/forge_ticket):
    #
    #    Name        Current Setting                            Required  Description
    #    ----        ---------------                            --------  -----------
    #    AES_KEY                                                no        The krbtgt/service AES key
    #    DOMAIN      windomain.local                            yes       The Domain (upper case) Ex: DEMO.LOCAL
    #    DOMAIN_SID  S-1-5-21-3541430928-2051711210-1391384369  yes       The Domain SID, Ex: S-1-5-21-1755879683-3641577184-3486455962
    #    DURATION    3650                                       yes       Duration of the ticket in days
    #    NTHASH      88E4D9FABAECF3DEC18DD80905521B29           no        The krbtgt/service nthash
    #    SPN         cifs/dc.windomain.local                    no        The Service Principal Name (Only used for silver ticket)
    #    USER        Administrator                              yes       The Domain User
    #    USER_RID    500                                        yes       The Domain User's relative identifier(RID)
    #
    #
    # View the full module info with the info, or info -d command.
    #
    # msf6 auxiliary(admin/kerberos/forge_ticket) > forge_silver
    #
    # [*] [2023.01.13-14:36:39] TGS MIT Credential Cache ticket saved to /Users/dwelch/.msf4/loot/20230113143639_default_unknown_mit.kerberos.cca_476516.bin
    # [*] Auxiliary module execution completed

    "\x05\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0f" \
    "\x57\x49\x4e\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00" \
    "\x00\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72" \
    "\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0f\x57\x49\x4e\x44" \
    "\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x00\x00\x0d\x41" \
    "\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x00\x00\x00\x01" \
    "\x00\x00\x00\x02\x00\x00\x00\x0f\x57\x49\x4e\x44\x4f\x4d\x41\x49" \
    "\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x00\x00\x04\x63\x69\x66\x73\x00" \
    "\x00\x00\x12\x64\x63\x2e\x77\x69\x6e\x64\x6f\x6d\x61\x69\x6e\x2e" \
    "\x6c\x6f\x63\x61\x6c\x00\x17\x00\x00\x00\x10\x66\x38\x37\x38\x64" \
    "\x64\x63\x36\x37\x38\x63\x37\x61\x64\x37\x66\x63\xc1\x6c\x77\x63" \
    "\xc1\x6c\x77\x76\x8d\x6f\x77\x76\x8d\x6f\x77\x00\x50\xa0\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xce\x61\x82\x03\xca" \
    "\x30\x82\x03\xc6\xa0\x03\x02\x01\x05\xa1\x11\x1b\x0f\x57\x49\x4e" \
    "\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa2\x25\x30\x23" \
    "\xa0\x03\x02\x01\x01\xa1\x1c\x30\x1a\x1b\x04\x63\x69\x66\x73\x1b" \
    "\x12\x64\x63\x2e\x77\x69\x6e\x64\x6f\x6d\x61\x69\x6e\x2e\x6c\x6f" \
    "\x63\x61\x6c\xa3\x82\x03\x83\x30\x82\x03\x7f\xa0\x03\x02\x01\x17" \
    "\xa1\x03\x02\x01\x02\xa2\x82\x03\x71\x04\x82\x03\x6d\x8f\x47\xbe" \
    "\x76\x3e\x3b\x6b\x9a\x85\x90\xc2\xbd\x0a\x62\x95\x3b\x6a\x93\xb9" \
    "\xab\x7f\xcd\xb4\x85\x9b\x48\x19\x85\xbd\xbb\xe3\xff\x21\xc0\x34" \
    "\xb3\x64\x72\xac\xad\x15\x88\x1f\x4d\xbb\xfd\x71\x4a\xc9\x2f\x89" \
    "\x4e\x9b\xf5\x73\x6f\xa3\x38\xdd\x33\x28\x4b\x0b\x0d\x20\xfc\x52" \
    "\x4c\x4b\xe5\xa5\xac\xe2\x06\xce\xa8\x0f\x56\x9e\x3f\xeb\x27\x10" \
    "\x59\x70\xd7\x78\x77\xd3\xad\x3c\xcd\x71\x19\x5d\x83\xbe\xbe\xc2" \
    "\x54\x7c\xd0\x38\x70\x7d\x8a\x7d\xb4\x10\x14\x06\x1d\xcb\x4c\xcf" \
    "\xe6\x80\xf3\xbe\x1a\xc8\xe5\xa0\x39\xff\xb1\x58\x93\x91\x4b\x8e" \
    "\x70\xff\x66\x70\x10\xe2\xfe\x15\xab\xf7\xb2\x31\x85\xa3\x67\xdb" \
    "\x8f\xc9\x8d\x43\x8e\x69\xf4\xf7\x4d\x3c\xfa\xf5\xad\xea\x3f\x8f" \
    "\x12\x4d\x95\x37\xee\x1a\x26\xcb\x60\xde\x00\x78\x7b\xe8\x89\xb6" \
    "\x25\x32\x39\x3a\xbf\xba\xb1\xd5\x14\xb0\x95\xc4\x1c\x37\xfa\x6d" \
    "\xbd\x5e\x2e\x9d\xdb\x3f\x23\x5c\xcf\xd3\xa6\xa5\xfa\xb8\xcf\x3c" \
    "\x16\x76\x0b\x57\xeb\x68\xa1\x72\x1b\xa7\x22\x82\xa0\xff\x79\xee" \
    "\xef\x7b\xa8\xe6\xe7\x6f\xcb\x47\xf8\x5b\x45\xcb\x0e\x40\x0b\x9b" \
    "\xd0\xe9\x98\xb4\x49\x4f\x9c\xf4\xbc\x34\xc1\x30\xf6\xb9\x79\xdc" \
    "\x51\x93\xda\xc4\x8e\x3a\xa5\xf3\xc9\x0e\x16\x7f\xf8\x1a\x5b\x24" \
    "\x2c\x45\xe6\xeb\xe5\x55\x3a\xfa\x6c\x79\x4f\x5e\x27\xe7\x94\x8b" \
    "\x2d\xeb\xde\x73\xe5\xc5\xaf\xdf\x24\x81\x5e\x62\x66\x33\xab\x7a" \
    "\x18\x6e\x64\xe5\xf5\x4c\x38\xc5\x2f\x92\x10\xea\x74\xaa\xe2\x9b" \
    "\x3d\x4a\xd3\xd1\x45\x9b\x8b\xe9\xd5\x83\x5d\x7a\x6c\x85\x12\x68" \
    "\x61\xfe\x16\xb2\x50\x26\x66\x09\x44\xcd\xf9\x5c\xff\xc4\x4a\x67" \
    "\xd1\x6a\x8b\xd5\xee\x81\x8f\xb2\xca\x0e\x23\x4b\x92\x6c\x62\x50" \
    "\x21\x6f\x70\x1c\x96\xd9\x9e\xb8\xf8\x0e\x06\x05\x53\x6b\x5b\x5c" \
    "\x0f\x04\xd8\x3a\xb0\x75\x73\x8f\x8a\x55\xa1\xf8\x56\x53\x96\x0e" \
    "\xe2\x84\x93\x3b\x5a\x05\xe2\x3f\x95\xc8\xb8\xfe\x29\xe9\x5f\x96" \
    "\xb6\x36\x30\xc0\x0a\x0a\x99\x23\xea\xff\xfb\xa4\x15\xe8\xfe\x1d" \
    "\xd1\xd4\x94\x49\x3b\x2a\x75\x2b\xdb\xae\xe4\x7b\x94\x61\x0b\xac" \
    "\x25\xfc\x0f\xd7\x6c\xc6\x5a\x4f\x8b\x7b\x5f\x77\x61\x3f\x24\xf2" \
    "\xe0\x77\xdd\x67\x7f\xac\xd8\x07\xaf\x68\x74\x5d\xa6\x4e\xec\x3f" \
    "\xa7\xff\x01\x73\x9a\x86\xaa\xb8\x8d\x11\x53\x77\xa1\xf2\xdb\xbe" \
    "\x5c\x75\xe4\x93\x52\x26\x95\xd6\x4e\x8a\x70\x7b\xca\xb2\xf3\x59" \
    "\x9c\xd3\x08\xb4\xe5\xcb\x64\x4d\x15\x30\x99\x6c\xe1\xed\x8e\xa3" \
    "\x06\x99\x30\x05\xa3\xd7\x43\x12\xeb\x2e\x46\xce\xca\x77\x7f\xba" \
    "\xe9\xad\x7b\xdd\x67\x0b\xb1\x15\x3b\x9c\x1a\xa6\x92\xd6\x9d\x59" \
    "\x1c\xe8\xed\x18\xbf\xf0\x11\xec\xa4\xa3\xce\x31\x43\xa8\x32\xb7" \
    "\x7f\x0a\xbd\x49\xe4\xd8\x45\x6f\x4d\x11\x2b\x24\x5f\x31\x8e\x90" \
    "\x41\x70\xf4\x0c\xa8\x1b\xd8\x70\xe4\x8b\x15\xf7\xe1\x58\x7d\xbe" \
    "\x0c\xcb\x52\x80\x72\xff\x24\xa8\xa6\xaf\x93\x8d\xb2\xcc\xe3\x16" \
    "\x43\x1c\x3a\xcc\xe5\x32\x4d\xc5\x4f\x82\x41\xdf\x64\x0c\xe8\xb1" \
    "\xb3\xf9\x6e\x5d\xa4\x90\x22\x24\x99\x65\x22\x4b\xc1\x37\xee\xa4" \
    "\x3d\x35\xaf\x62\x78\x75\xe7\x68\x65\xb4\xa0\x24\x3b\xeb\x0c\x4a" \
    "\x5e\x8e\xf1\x29\x34\xc5\x73\x01\x7b\xd9\x36\xed\x90\xa9\x90\xdb" \
    "\x4a\xef\xb4\x2f\xc3\x9a\xd7\xb2\x4e\x1e\x1a\x68\xb1\x45\x8d\x98" \
    "\x6f\x1f\x88\x67\x06\x4e\x2e\x92\x33\x92\x8b\x5e\xab\xaa\x57\x19" \
    "\xb9\x77\xe1\x3a\xdb\xc1\x66\xa5\xad\xaa\xbb\x6c\x47\xa8\xab\xd5" \
    "\xe7\x65\xe3\xcf\xa2\xaf\x7d\xcb\x8e\xcd\x63\x4c\x6a\x5d\x47\x8e" \
    "\xc8\x90\x93\x31\x70\x00\x50\xe4\x41\x31\xc0\xe4\x6d\x5b\x95\x49" \
    "\x8f\x89\xb5\xb4\xea\xc9\x60\xc4\x3a\x4a\x16\x69\x3c\x29\x7a\xd9" \
    "\xf4\xff\x84\xb0\xfa\xa9\xaa\xac\x47\xb1\xa4\x98\x64\xe4\xc3\xaa" \
    "\x26\x10\x9c\x38\x8f\x60\xeb\x29\xfa\x15\xe7\x4b\xe4\x39\xb4\xed" \
    "\x13\x87\x4b\x91\x8f\x89\xbe\x0c\x01\x13\x19\xf7\xef\xbc\x93\x23" \
    "\xfc\xea\x3c\xb3\xd7\xbc\x0e\x00\xb5\xa7\xbf\x06\x73\xad\x5b\x79" \
    "\x12\x17\x17\x3f\xc2\x80\x6a\x0f\x69\xb0\x12\x49\x56\xc2\xe3\xbd" \
    "\x69\x77\x82\x75\x30\xa3\xc7\x96\x06\xee\x00\x00\x00\x00"
  end

  # Identical to `:ccache_aes` but converted to kirbi file format (via `admin/kerberos/ticket_converter`)
  let(:kirbi_aes) do
    "\x76\x82\x04\xf5\x30\x82\x04\xf1\xa0\x03\x02\x01\x05\xa1\x03\x02" \
    "\x01\x16\xa2\x82\x03\xd6\x30\x82\x03\xd2\x61\x82\x03\xce\x30\x82" \
    "\x03\xca\xa0\x03\x02\x01\x05\xa1\x11\x1b\x0f\x57\x49\x4e\x44\x4f" \
    "\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa2\x25\x30\x23\xa0\x03" \
    "\x02\x01\x01\xa1\x1c\x30\x1a\x1b\x04\x63\x69\x66\x73\x1b\x12\x64" \
    "\x63\x2e\x77\x69\x6e\x64\x6f\x6d\x61\x69\x6e\x2e\x6c\x6f\x63\x61" \
    "\x6c\xa3\x82\x03\x87\x30\x82\x03\x83\xa0\x03\x02\x01\x12\xa1\x03" \
    "\x02\x01\x02\xa2\x82\x03\x75\x04\x82\x03\x71\xec\x7a\xb2\xbf\x57" \
    "\x69\x55\x02\x0e\x1f\xf3\xeb\xdb\x0e\x37\x42\x67\x48\x62\xbb\x63" \
    "\x40\x9b\xc9\x70\x73\x03\x46\x8c\xdc\x4f\x4c\xcf\x8e\x66\xf1\xd7" \
    "\xad\x07\x68\x00\x5d\xec\xea\xe8\x0b\x79\x9c\x2e\x18\xac\x40\x92" \
    "\x0c\xf0\xcf\xdd\xaf\x4b\x9f\xf3\x3f\xcf\x59\x2e\xb3\x7b\x99\x74" \
    "\x80\x57\x8f\x74\xf2\xa1\xe6\xfc\x08\x60\x74\x30\xd2\x0b\x7f\xfd" \
    "\xd1\x4c\xa5\x1f\xb5\xd5\xe1\xfe\xa8\x62\xca\x5b\xf2\xad\xd0\xbd" \
    "\x1f\x2f\x8b\x60\xe0\xa6\x0a\xc7\xe7\xff\x08\xae\xb9\x2b\xcd\xa9" \
    "\x4a\xee\xd0\x68\x53\xa3\xed\xc4\xa0\x75\x3b\xc8\x0e\x6c\x47\x90" \
    "\x38\x92\xe7\x37\xa6\x27\xa4\x2e\xd6\x54\xa4\x9c\x30\xd6\xf5\xea" \
    "\x33\x68\x1c\x26\xea\x7e\xf8\x80\xe9\x94\x52\x2c\x68\xef\x8f\x98" \
    "\x6a\x32\xd1\xa2\x37\xd5\x44\xf5\x80\x64\x9b\x22\xe8\xb9\x20\x4b" \
    "\xf7\x00\x49\xbe\xab\x6f\xcb\x19\x59\x23\x80\xad\x86\x33\xeb\x52" \
    "\x0d\xbb\xf8\xf1\x9d\xd9\x7e\xfc\xf6\x88\x66\x24\x5d\xf0\x40\xbf" \
    "\x0e\x91\x17\x8b\x9e\x62\x34\xa5\x6e\x7d\x43\x7e\xcc\x4e\xbf\x66" \
    "\xab\x8b\xd0\xb1\x44\xa1\x7b\xe1\x89\x78\x38\xe3\xe1\x48\x70\x4d" \
    "\x1f\xfe\xc4\xb0\x5b\x70\x56\x66\xc2\x8f\x5e\x56\x3e\x2f\x18\x95" \
    "\x4b\x4c\x5a\x70\x06\x0b\xf6\x34\x7a\x2a\x27\x81\xa0\x96\xc2\x06" \
    "\x46\x29\x39\x38\xd9\x60\x56\xd3\x9d\x7f\x2a\x43\x66\x57\xec\x93" \
    "\x46\x19\x84\x16\x25\xd8\xc9\xa9\x37\xd8\xe5\xe1\xdd\x65\x07\xc7" \
    "\x35\xc3\x20\x10\x7a\x43\xf3\x71\x1f\x33\xdd\x1b\xd9\xac\xb2\x85" \
    "\xd7\x4f\xd0\x95\x1e\x76\x51\x47\x27\xa5\x4e\xf2\x23\x8a\xbe\xae" \
    "\xbd\x66\xbe\xeb\xca\x62\x49\x2b\x4e\xce\xa4\x1f\xfb\x89\x0a\xe5" \
    "\xa9\x8b\xfa\xd8\x6b\x12\x4d\x0b\xd3\x4e\xc9\x17\x49\x33\xc1\xec" \
    "\x1a\xa4\x99\xfa\xc3\xc1\x81\x82\x71\x07\x34\xe5\x6b\x87\x88\x17" \
    "\xce\x79\xa8\xb6\xbc\x70\x46\x4a\xc9\xcd\x7d\x93\xd8\xb5\x69\x79" \
    "\xa0\x89\x3c\x9e\xaa\xf2\x1d\x68\xb1\x63\xd0\xfb\x81\xff\x1e\x77" \
    "\xb7\xc9\x98\xaf\xe6\xe0\x02\xda\xd7\x88\x4f\xa7\xc6\x31\xb1\x39" \
    "\x65\xb4\x80\x36\x2a\x12\x08\xbb\x1e\xba\xd8\xcb\x97\x70\xeb\xcc" \
    "\x9b\x32\xfa\x4b\xd4\xa9\x50\x5d\x6a\xe2\x0f\x02\xa9\xd1\x03\x59" \
    "\x40\x4f\x79\xe7\x09\xf3\x6d\x57\x10\xfe\xff\x56\xff\xc1\x4c\xb8" \
    "\x47\xc1\x33\x1b\xc5\x84\x89\xbf\xc5\x60\x23\x1d\x62\xdc\x07\x34" \
    "\x24\x51\x6c\x60\x55\x3b\x30\xe3\x26\x7c\xcc\x73\x50\xee\x27\xe8" \
    "\xd4\xad\x1a\x9b\xfe\xb1\x66\xb5\xb6\x41\xc9\x9b\x1c\x33\x17\x09" \
    "\x38\x47\xf1\x2f\x9c\xdd\xbe\xc4\x0b\x61\x14\xf0\xbd\xe0\xc3\xc2" \
    "\x8c\x3e\x2b\x06\xe0\xf2\x74\x2e\xc1\x74\x19\x7c\x4c\xe8\xf5\x45" \
    "\x69\x40\xdd\xfb\xab\x0f\x8c\x0e\x21\x35\xcf\xc4\x73\x82\x47\x47" \
    "\xe1\xb8\x82\x3d\x87\x02\x5c\xb1\x47\xee\x51\x15\xda\xa6\x92\xa8" \
    "\x3e\x5b\x38\x61\x93\x6c\x87\x03\xe8\x68\x78\x19\x1d\xec\x61\xe1" \
    "\x03\x07\x98\xdd\xf7\xbc\x6e\x1f\x73\x79\xad\xb0\x4d\x99\x39\x6d" \
    "\xfa\xd6\xc2\x29\x4f\xa6\x4e\x60\x4a\x35\x09\x17\x1d\x9d\x75\xaa" \
    "\x5b\x27\x24\xec\xb0\x82\xee\x94\xe0\xb7\xdf\xbc\xc6\x16\xf9\x11" \
    "\x86\xe2\x09\xd3\xe6\x1b\x11\x57\x85\x22\x5e\x17\x71\x8f\x7b\x25" \
    "\xde\xbb\x03\x67\x05\xde\x3e\x24\x9f\x02\xe6\xab\xc3\xf8\x3f\x3d" \
    "\x0e\x64\x5b\x0a\xa3\xfe\x1c\x3c\x47\xb1\xce\x45\x3e\x83\x71\xde" \
    "\xd6\x6f\x35\xa7\xe1\x31\x5b\x65\x46\x58\x2d\xf0\xca\xc7\x85\x0d" \
    "\x42\x40\x09\xe0\x83\x8a\x86\x2c\xc4\xfc\xa8\x3d\x51\xc3\x72\x00" \
    "\x1d\x72\xe1\x65\x31\xe3\xf4\xd6\xe0\x37\x0a\x48\x24\xa5\x02\xcc" \
    "\x96\x9d\x9a\x81\x9e\xd9\xc6\x6c\x2d\xb2\x09\xac\x34\x17\x57\xa8" \
    "\x80\x89\x63\xfc\x03\xf7\xb6\x3c\x9f\x38\x95\xf0\x72\xff\x4d\x79" \
    "\xf0\x6e\x1f\x98\x20\x2f\x5d\xd2\xc9\xd1\xaa\x20\x35\xac\x92\x5e" \
    "\x62\x20\x29\x3d\xdf\xb1\x1b\xbd\x91\x40\x69\xae\xdf\xa6\x78\x00" \
    "\xbe\xcb\x26\xd7\x7a\xd4\xcf\x31\x55\xa8\xc4\x5d\xfa\x27\xf5\x44" \
    "\xc0\x2b\xb4\x94\x66\x78\xd6\xaa\x66\x6c\x05\xa4\x99\x3c\x77\xdf" \
    "\xd0\x26\x47\xb4\x40\x90\xae\x8a\x96\x02\xe0\xf3\x22\xf0\x8d\xbb" \
    "\x0d\x86\x5b\x0a\x7d\x7a\xee\x38\x45\xd3\x01\x46\xa3\x82\x01\x09" \
    "\x30\x82\x01\x05\xa0\x03\x02\x01\x12\xa2\x81\xfd\x04\x81\xfa\x7d" \
    "\x81\xf7\x30\x81\xf4\xa0\x81\xf1\x30\x81\xee\x30\x81\xeb\xa0\x2b" \
    "\x30\x29\xa0\x03\x02\x01\x12\xa1\x22\x04\x20\x30\x31\x36\x30\x31" \
    "\x30\x31\x30\x37\x65\x65\x30\x64\x36\x38\x38\x63\x39\x39\x61\x39" \
    "\x33\x38\x38\x36\x33\x34\x61\x65\x30\x34\x31\xa1\x11\x1b\x0f\x57" \
    "\x49\x4e\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa2\x1a" \
    "\x30\x18\xa0\x03\x02\x01\x01\xa1\x11\x30\x0f\x1b\x0d\x41\x64\x6d" \
    "\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\xa3\x07\x03\x05\x00\x50" \
    "\xa0\x00\x00\xa4\x11\x18\x0f\x32\x30\x32\x33\x30\x31\x31\x33\x31" \
    "\x34\x33\x31\x32\x35\x5a\xa5\x11\x18\x0f\x32\x30\x32\x33\x30\x31" \
    "\x31\x33\x31\x34\x33\x31\x32\x35\x5a\xa6\x11\x18\x0f\x32\x30\x33" \
    "\x33\x30\x31\x31\x30\x31\x34\x33\x31\x32\x35\x5a\xa7\x11\x18\x0f" \
    "\x32\x30\x33\x33\x30\x31\x31\x30\x31\x34\x33\x31\x32\x35\x5a\xa8" \
    "\x11\x1b\x0f\x57\x49\x4e\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43" \
    "\x41\x4c\xa9\x25\x30\x23\xa0\x03\x02\x01\x01\xa1\x1c\x30\x1a\x1b" \
    "\x04\x63\x69\x66\x73\x1b\x12\x64\x63\x2e\x77\x69\x6e\x64\x6f\x6d" \
    "\x61\x69\x6e\x2e\x6c\x6f\x63\x61\x6c"
  end

  # Identical to `:ccache_nthash` but converted to kirbi file format (via `admin/kerberos/ticket_converter`)
  let(:kirbi_nthash) do
    "\x76\x82\x04\xdf\x30\x82\x04\xdb\xa0\x03\x02\x01\x05\xa1\x03\x02" \
    "\x01\x16\xa2\x82\x03\xd2\x30\x82\x03\xce\x61\x82\x03\xca\x30\x82" \
    "\x03\xc6\xa0\x03\x02\x01\x05\xa1\x11\x1b\x0f\x57\x49\x4e\x44\x4f" \
    "\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa2\x25\x30\x23\xa0\x03" \
    "\x02\x01\x01\xa1\x1c\x30\x1a\x1b\x04\x63\x69\x66\x73\x1b\x12\x64" \
    "\x63\x2e\x77\x69\x6e\x64\x6f\x6d\x61\x69\x6e\x2e\x6c\x6f\x63\x61" \
    "\x6c\xa3\x82\x03\x83\x30\x82\x03\x7f\xa0\x03\x02\x01\x17\xa1\x03" \
    "\x02\x01\x02\xa2\x82\x03\x71\x04\x82\x03\x6d\x8f\x47\xbe\x76\x3e" \
    "\x3b\x6b\x9a\x85\x90\xc2\xbd\x0a\x62\x95\x3b\x6a\x93\xb9\xab\x7f" \
    "\xcd\xb4\x85\x9b\x48\x19\x85\xbd\xbb\xe3\xff\x21\xc0\x34\xb3\x64" \
    "\x72\xac\xad\x15\x88\x1f\x4d\xbb\xfd\x71\x4a\xc9\x2f\x89\x4e\x9b" \
    "\xf5\x73\x6f\xa3\x38\xdd\x33\x28\x4b\x0b\x0d\x20\xfc\x52\x4c\x4b" \
    "\xe5\xa5\xac\xe2\x06\xce\xa8\x0f\x56\x9e\x3f\xeb\x27\x10\x59\x70" \
    "\xd7\x78\x77\xd3\xad\x3c\xcd\x71\x19\x5d\x83\xbe\xbe\xc2\x54\x7c" \
    "\xd0\x38\x70\x7d\x8a\x7d\xb4\x10\x14\x06\x1d\xcb\x4c\xcf\xe6\x80" \
    "\xf3\xbe\x1a\xc8\xe5\xa0\x39\xff\xb1\x58\x93\x91\x4b\x8e\x70\xff" \
    "\x66\x70\x10\xe2\xfe\x15\xab\xf7\xb2\x31\x85\xa3\x67\xdb\x8f\xc9" \
    "\x8d\x43\x8e\x69\xf4\xf7\x4d\x3c\xfa\xf5\xad\xea\x3f\x8f\x12\x4d" \
    "\x95\x37\xee\x1a\x26\xcb\x60\xde\x00\x78\x7b\xe8\x89\xb6\x25\x32" \
    "\x39\x3a\xbf\xba\xb1\xd5\x14\xb0\x95\xc4\x1c\x37\xfa\x6d\xbd\x5e" \
    "\x2e\x9d\xdb\x3f\x23\x5c\xcf\xd3\xa6\xa5\xfa\xb8\xcf\x3c\x16\x76" \
    "\x0b\x57\xeb\x68\xa1\x72\x1b\xa7\x22\x82\xa0\xff\x79\xee\xef\x7b" \
    "\xa8\xe6\xe7\x6f\xcb\x47\xf8\x5b\x45\xcb\x0e\x40\x0b\x9b\xd0\xe9" \
    "\x98\xb4\x49\x4f\x9c\xf4\xbc\x34\xc1\x30\xf6\xb9\x79\xdc\x51\x93" \
    "\xda\xc4\x8e\x3a\xa5\xf3\xc9\x0e\x16\x7f\xf8\x1a\x5b\x24\x2c\x45" \
    "\xe6\xeb\xe5\x55\x3a\xfa\x6c\x79\x4f\x5e\x27\xe7\x94\x8b\x2d\xeb" \
    "\xde\x73\xe5\xc5\xaf\xdf\x24\x81\x5e\x62\x66\x33\xab\x7a\x18\x6e" \
    "\x64\xe5\xf5\x4c\x38\xc5\x2f\x92\x10\xea\x74\xaa\xe2\x9b\x3d\x4a" \
    "\xd3\xd1\x45\x9b\x8b\xe9\xd5\x83\x5d\x7a\x6c\x85\x12\x68\x61\xfe" \
    "\x16\xb2\x50\x26\x66\x09\x44\xcd\xf9\x5c\xff\xc4\x4a\x67\xd1\x6a" \
    "\x8b\xd5\xee\x81\x8f\xb2\xca\x0e\x23\x4b\x92\x6c\x62\x50\x21\x6f" \
    "\x70\x1c\x96\xd9\x9e\xb8\xf8\x0e\x06\x05\x53\x6b\x5b\x5c\x0f\x04" \
    "\xd8\x3a\xb0\x75\x73\x8f\x8a\x55\xa1\xf8\x56\x53\x96\x0e\xe2\x84" \
    "\x93\x3b\x5a\x05\xe2\x3f\x95\xc8\xb8\xfe\x29\xe9\x5f\x96\xb6\x36" \
    "\x30\xc0\x0a\x0a\x99\x23\xea\xff\xfb\xa4\x15\xe8\xfe\x1d\xd1\xd4" \
    "\x94\x49\x3b\x2a\x75\x2b\xdb\xae\xe4\x7b\x94\x61\x0b\xac\x25\xfc" \
    "\x0f\xd7\x6c\xc6\x5a\x4f\x8b\x7b\x5f\x77\x61\x3f\x24\xf2\xe0\x77" \
    "\xdd\x67\x7f\xac\xd8\x07\xaf\x68\x74\x5d\xa6\x4e\xec\x3f\xa7\xff" \
    "\x01\x73\x9a\x86\xaa\xb8\x8d\x11\x53\x77\xa1\xf2\xdb\xbe\x5c\x75" \
    "\xe4\x93\x52\x26\x95\xd6\x4e\x8a\x70\x7b\xca\xb2\xf3\x59\x9c\xd3" \
    "\x08\xb4\xe5\xcb\x64\x4d\x15\x30\x99\x6c\xe1\xed\x8e\xa3\x06\x99" \
    "\x30\x05\xa3\xd7\x43\x12\xeb\x2e\x46\xce\xca\x77\x7f\xba\xe9\xad" \
    "\x7b\xdd\x67\x0b\xb1\x15\x3b\x9c\x1a\xa6\x92\xd6\x9d\x59\x1c\xe8" \
    "\xed\x18\xbf\xf0\x11\xec\xa4\xa3\xce\x31\x43\xa8\x32\xb7\x7f\x0a" \
    "\xbd\x49\xe4\xd8\x45\x6f\x4d\x11\x2b\x24\x5f\x31\x8e\x90\x41\x70" \
    "\xf4\x0c\xa8\x1b\xd8\x70\xe4\x8b\x15\xf7\xe1\x58\x7d\xbe\x0c\xcb" \
    "\x52\x80\x72\xff\x24\xa8\xa6\xaf\x93\x8d\xb2\xcc\xe3\x16\x43\x1c" \
    "\x3a\xcc\xe5\x32\x4d\xc5\x4f\x82\x41\xdf\x64\x0c\xe8\xb1\xb3\xf9" \
    "\x6e\x5d\xa4\x90\x22\x24\x99\x65\x22\x4b\xc1\x37\xee\xa4\x3d\x35" \
    "\xaf\x62\x78\x75\xe7\x68\x65\xb4\xa0\x24\x3b\xeb\x0c\x4a\x5e\x8e" \
    "\xf1\x29\x34\xc5\x73\x01\x7b\xd9\x36\xed\x90\xa9\x90\xdb\x4a\xef" \
    "\xb4\x2f\xc3\x9a\xd7\xb2\x4e\x1e\x1a\x68\xb1\x45\x8d\x98\x6f\x1f" \
    "\x88\x67\x06\x4e\x2e\x92\x33\x92\x8b\x5e\xab\xaa\x57\x19\xb9\x77" \
    "\xe1\x3a\xdb\xc1\x66\xa5\xad\xaa\xbb\x6c\x47\xa8\xab\xd5\xe7\x65" \
    "\xe3\xcf\xa2\xaf\x7d\xcb\x8e\xcd\x63\x4c\x6a\x5d\x47\x8e\xc8\x90" \
    "\x93\x31\x70\x00\x50\xe4\x41\x31\xc0\xe4\x6d\x5b\x95\x49\x8f\x89" \
    "\xb5\xb4\xea\xc9\x60\xc4\x3a\x4a\x16\x69\x3c\x29\x7a\xd9\xf4\xff" \
    "\x84\xb0\xfa\xa9\xaa\xac\x47\xb1\xa4\x98\x64\xe4\xc3\xaa\x26\x10" \
    "\x9c\x38\x8f\x60\xeb\x29\xfa\x15\xe7\x4b\xe4\x39\xb4\xed\x13\x87" \
    "\x4b\x91\x8f\x89\xbe\x0c\x01\x13\x19\xf7\xef\xbc\x93\x23\xfc\xea" \
    "\x3c\xb3\xd7\xbc\x0e\x00\xb5\xa7\xbf\x06\x73\xad\x5b\x79\x12\x17" \
    "\x17\x3f\xc2\x80\x6a\x0f\x69\xb0\x12\x49\x56\xc2\xe3\xbd\x69\x77" \
    "\x82\x75\x30\xa3\xc7\x96\x06\xee\xa3\x81\xf8\x30\x81\xf5\xa0\x03" \
    "\x02\x01\x17\xa2\x81\xed\x04\x81\xea\x7d\x81\xe7\x30\x81\xe4\xa0" \
    "\x81\xe1\x30\x81\xde\x30\x81\xdb\xa0\x1b\x30\x19\xa0\x03\x02\x01" \
    "\x17\xa1\x12\x04\x10\x66\x38\x37\x38\x64\x64\x63\x36\x37\x38\x63" \
    "\x37\x61\x64\x37\x66\xa1\x11\x1b\x0f\x57\x49\x4e\x44\x4f\x4d\x41" \
    "\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa2\x1a\x30\x18\xa0\x03\x02\x01" \
    "\x01\xa1\x11\x30\x0f\x1b\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74\x72" \
    "\x61\x74\x6f\x72\xa3\x07\x03\x05\x00\x50\xa0\x00\x00\xa4\x11\x18" \
    "\x0f\x32\x30\x32\x33\x30\x31\x31\x33\x31\x34\x33\x36\x33\x39\x5a" \
    "\xa5\x11\x18\x0f\x32\x30\x32\x33\x30\x31\x31\x33\x31\x34\x33\x36" \
    "\x33\x39\x5a\xa6\x11\x18\x0f\x32\x30\x33\x33\x30\x31\x31\x30\x31" \
    "\x34\x33\x36\x33\x39\x5a\xa7\x11\x18\x0f\x32\x30\x33\x33\x30\x31" \
    "\x31\x30\x31\x34\x33\x36\x33\x39\x5a\xa8\x11\x1b\x0f\x57\x49\x4e" \
    "\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa9\x25\x30\x23" \
    "\xa0\x03\x02\x01\x01\xa1\x1c\x30\x1a\x1b\x04\x63\x69\x66\x73\x1b" \
    "\x12\x64\x63\x2e\x77\x69\x6e\x64\x6f\x6d\x61\x69\x6e\x2e\x6c\x6f" \
    "\x63\x61\x6c"
  end

  let(:ccache_file_aes) do
    ccache_file = Tempfile.new('ccache_aes')
    File.binwrite(ccache_file.path, ccache_aes)
    ccache_file
  end

  let(:ccache_file_nthash) do
    ccache_file = Tempfile.new('ccache_nthash')
    File.binwrite(ccache_file.path, ccache_nthash)
    ccache_file
  end

  let(:kirbi_file_aes) do
    kirbi_file = Tempfile.new('kirbi_aes')
    File.binwrite(kirbi_file.path, kirbi_aes)
    kirbi_file
  end

  let(:kirbi_file_nthash) do
    kirbi_file = Tempfile.new('kirbi_nthash')
    File.binwrite(kirbi_file.path, kirbi_nthash)
    kirbi_file
  end

  let(:expected_decrypted_aes_output) do
    expected_output = ["#{file_format} File:#{ticket_path}"]
    expected_output << <<~EOF.chomp
      Primary Principal: Administrator@WINDOMAIN.LOCAL
      Ccache version: 4

      Creds: 1
        Credential[0]:
          Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
          Client: Administrator@WINDOMAIN.LOCAL
          Ticket etype: 18 (AES256)
          Key: 3031363031303130376565306436383863393961393338383633346165303431
          Subkey: false
          Ticket Length: 978
          Ticket Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
          Addresses: 0
          Authdatas: 0
          Times:
            Auth time: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
            Start time: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
            End time: #{Time.parse('2033-01-10 14:31:25 UTC').to_time}
            Renew Till: #{Time.parse('2033-01-10 14:31:25 UTC').to_time}
          Ticket:
            Ticket Version Number: 5
            Realm: WINDOMAIN.LOCAL
            Server Name: cifs/dc.windomain.local
            Encrypted Ticket Part:
              Ticket etype: 18 (AES256)
              Key Version Number: 2
              Decrypted (with key: 4b912be0366a6f37f4a7d571bee18b1173d93195ef76f8d1e3e81ef6172ab326):
                Times:
                  Auth time: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
                  Start time: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
                  End time: #{Time.parse('2033-01-10 14:31:25 UTC').to_time}
                  Renew Till: #{Time.parse('2033-01-10 14:31:25 UTC').to_time}
                Client Addresses: 0
                Transited: tr_type: 0, Contents: ""
                Client Name: 'Administrator'
                Client Realm: 'WINDOMAIN.LOCAL'
                Ticket etype: 18 (AES256)
                Session Key: 3031363031303130376565306436383863393961393338383633346165303431
                Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
                PAC:
                  Validation Info:
                    Logon Time: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
                    Logoff Time: Never Expires (inf)
                    Kick Off Time: Never Expires (inf)
                    Password Last Set: No Time Set (0)
                    Password Can Change: No Time Set (0)
                    Password Must Change: Never Expires (inf)
                    Logon Count: 0
                    Bad Password Count: 0
                    User ID: 500
                    Primary Group ID: 513
                    User Flags: 0
                      .... .... .... .... ..0. .... .... .... Used Lmv2 Auth And Ntlmv2 Session Key: The USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY bit is NOT SET
                      .... .... .... .... ...0 .... .... .... Used Lmv2 Auth And Session Key: The USED_LMV2_AUTH_AND_SESSION_KEY bit is NOT SET
                      .... .... .... .... .... 0... .... .... Used Ntlmv2 Auth And Session Key: The USED_NTLMV2_AUTH_AND_SESSION_KEY bit is NOT SET
                      .... .... .... .... .... .0.. .... .... Profile Path Populated: The PROFILE_PATH_POPULATED bit is NOT SET
                      .... .... .... .... .... ..0. .... .... Resource Group Ids: The RESOURCE_GROUP_IDS bit is NOT SET
                      .... .... .... .... .... ...0 .... .... Accepts Ntlmv2: The ACCEPTS_NTLMV2 bit is NOT SET
                      .... .... .... .... .... .... 0... .... Machine Account: The MACHINE_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .0.. .... Sub Authentication: The SUB_AUTHENTICATION bit is NOT SET
                      .... .... .... .... .... .... ..0. .... Extra Sids: The EXTRA_SIDS bit is NOT SET
                      .... .... .... .... .... .... .... 0... Lan Manager: The LAN_MANAGER bit is NOT SET
                      .... .... .... .... .... .... .... ..0. No Encryption: The NO_ENCRYPTION bit is NOT SET
                      .... .... .... .... .... .... .... ...0 Guest: The GUEST bit is NOT SET
                    User Session Key: 00000000000000000000000000000000
                    User Account Control: 528
                      .... .... ..0. .... .... .... .... .... Use Aes Keys: The USE_AES_KEYS bit is NOT SET
                      .... .... ...0 .... .... .... .... .... Partial Secrets Account: The PARTIAL_SECRETS_ACCOUNT bit is NOT SET
                      .... .... .... 0... .... .... .... .... No Auth Data Required: The NO_AUTH_DATA_REQUIRED bit is NOT SET
                      .... .... .... .0.. .... .... .... .... Trusted To Authenticate For Delegation: The TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit is NOT SET
                      .... .... .... ..0. .... .... .... .... Password Expired: The PASSWORD_EXPIRED bit is NOT SET
                      .... .... .... ...0 .... .... .... .... Dont Require Preauth: The DONT_REQUIRE_PREAUTH bit is NOT SET
                      .... .... .... .... 0... .... .... .... Use Des Key Only: The USE_DES_KEY_ONLY bit is NOT SET
                      .... .... .... .... .0.. .... .... .... Not Delegated: The NOT_DELEGATED bit is NOT SET
                      .... .... .... .... ..0. .... .... .... Trusted For Delegation: The TRUSTED_FOR_DELEGATION bit is NOT SET
                      .... .... .... .... ...0 .... .... .... Smartcard Required: The SMARTCARD_REQUIRED bit is NOT SET
                      .... .... .... .... .... 0... .... .... Encrypted Test Password Allowed: The ENCRYPTED_TEST_PASSWORD_ALLOWED bit is NOT SET
                      .... .... .... .... .... .0.. .... .... Account Auto Lock: The ACCOUNT_AUTO_LOCK bit is NOT SET
                      .... .... .... .... .... ..1. .... .... Dont Expire Password: The DONT_EXPIRE_PASSWORD bit is SET
                      .... .... .... .... .... ...0 .... .... Server Trust Account: The SERVER_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... 0... .... Workstation Trust Account: The WORKSTATION_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .0.. .... Interdomain Trust Account: The INTERDOMAIN_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... ..0. .... Mns Logon Account: The MNS_LOGON_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... ...1 .... Normal Account: The NORMAL_ACCOUNT bit is SET
                      .... .... .... .... .... .... .... 0... Temp Duplicate Account: The TEMP_DUPLICATE_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .... .0.. Password Not Required: The PASSWORD_NOT_REQUIRED bit is NOT SET
                      .... .... .... .... .... .... .... ..0. Home Directory Required: The HOME_DIRECTORY_REQUIRED bit is NOT SET
                      .... .... .... .... .... .... .... ...0 Account Disabled: The ACCOUNT_DISABLED bit is NOT SET
                    Sub Auth Status: 0
                    Last Successful Interactive Logon: No Time Set (0)
                    Last Failed Interactive Logon: No Time Set (0)
                    Failed Interactive Logon Count: 0
                    Extra SID Count: 0
                    Resource Group Count: 0
                    Group Count: 5
                    Group IDs:
                      Relative ID: 513
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 512
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 520
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 518
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 519
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                    Logon Domain ID: S-1-5-21-3541430928-2051711210-1391384369
                    Effective Name: 'Administrator'
                    Full Name: ''
                    Logon Script: ''
                    Profile Path: ''
                    Home Directory: ''
                    Home Directory Drive: ''
                    Logon Server: ''
                    Logon Domain Name: 'WINDOMAIN.LOCAL'
                  Client Info:
                    Name: 'Administrator'
                    Client ID: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
                  Pac Server Checksum:
                    Signature: 81a20da731b3b9bdd2e756dc
                  Pac Privilege Server Checksum:
                    Signature: e552ba92ad312755d89ebcc7
    EOF
    expected_output.join("\n")
  end

  let(:expected_encrypted_aes_output) do
    expected_output = ['No decryption key provided proceeding without decryption.']
    expected_output << "#{file_format} File:#{ticket_path}"
    expected_output << <<~EOF.chomp
      Primary Principal: Administrator@WINDOMAIN.LOCAL
      Ccache version: 4

      Creds: 1
        Credential[0]:
          Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
          Client: Administrator@WINDOMAIN.LOCAL
          Ticket etype: 18 (AES256)
          Key: 3031363031303130376565306436383863393961393338383633346165303431
          Subkey: false
          Ticket Length: 978
          Ticket Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
          Addresses: 0
          Authdatas: 0
          Times:
            Auth time: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
            Start time: #{Time.parse('2023-01-13 14:31:25 UTC').to_time}
            End time: #{Time.parse('2033-01-10 14:31:25 UTC').to_time}
            Renew Till: #{Time.parse('2033-01-10 14:31:25 UTC').to_time}
          Ticket:
            Ticket Version Number: 5
            Realm: WINDOMAIN.LOCAL
            Server Name: cifs/dc.windomain.local
            Encrypted Ticket Part:
              Ticket etype: 18 (AES256)
              Key Version Number: 2
              Cipher:
                7Hqyv1dpVQIOH/Pr2w43QmdIYrtjQJvJcHMDRozcT0zPjmbx160HaABd7OroC3mcLhisQJIM8M/dr0uf8z/PWS6ze5l0gFePdPKh5vwIYHQw0gt//dFMpR+11eH+qGLKW/Kt0L0fL4tg4KYKx+f/CK65K82pSu7QaFOj7cSgdTvIDmxHkDiS5zemJ6Qu1lSknDDW9eozaBwm6n74gOmUUixo74+YajLRojfVRPWAZJsi6LkgS/cASb6rb8sZWSOArYYz61INu/jxndl+/PaIZiRd8EC/DpEXi55iNKVufUN+zE6/ZquL0LFEoXvhiXg44+FIcE0f/sSwW3BWZsKPXlY+LxiVS0xacAYL9jR6KieBoJbCBkYpOTjZYFbTnX8qQ2ZX7JNGGYQWJdjJqTfY5eHdZQfHNcMgEHpD83EfM90b2ayyhddP0JUedlFHJ6VO8iOKvq69Zr7rymJJK07OpB/7iQrlqYv62GsSTQvTTskXSTPB7BqkmfrDwYGCcQc05WuHiBfOeai2vHBGSsnNfZPYtWl5oIk8nqryHWixY9D7gf8ed7fJmK/m4ALa14hPp8YxsTlltIA2KhIIux662MuXcOvMmzL6S9SpUF1q4g8CqdEDWUBPeecJ821XEP7/Vv/BTLhHwTMbxYSJv8VgIx1i3Ac0JFFsYFU7MOMmfMxzUO4n6NStGpv+sWa1tkHJmxwzFwk4R/EvnN2+xAthFPC94MPCjD4rBuDydC7BdBl8TOj1RWlA3furD4wOITXPxHOCR0fhuII9hwJcsUfuURXappKoPls4YZNshwPoaHgZHexh4QMHmN33vG4fc3mtsE2ZOW361sIpT6ZOYEo1CRcdnXWqWyck7LCC7pTgt9+8xhb5EYbiCdPmGxFXhSJeF3GPeyXeuwNnBd4+JJ8C5qvD+D89DmRbCqP+HDxHsc5FPoNx3tZvNafhMVtlRlgt8MrHhQ1CQAngg4qGLMT8qD1Rw3IAHXLhZTHj9NbgNwpIJKUCzJadmoGe2cZsLbIJrDQXV6iAiWP8A/e2PJ84lfBy/0158G4fmCAvXdLJ0aogNaySXmIgKT3fsRu9kUBprt+meAC+yybXetTPMVWoxF36J/VEwCu0lGZ41qpmbAWkmTx339AmR7RAkK6KlgLg8yLwjbsNhlsKfXruOEXTAUY=
    EOF
    expected_output.join("\n")
  end

  let(:expected_decrypted_nthash_output) do
    expected_output = ["#{file_format} File:#{ticket_path}"]
    expected_output << <<~EOF.chomp
      Primary Principal: Administrator@WINDOMAIN.LOCAL
      Ccache version: 4

      Creds: 1
        Credential[0]:
          Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
          Client: Administrator@WINDOMAIN.LOCAL
          Ticket etype: 23 (RC4_HMAC)
          Key: 66383738646463363738633761643766
          Subkey: false
          Ticket Length: 974
          Ticket Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
          Addresses: 0
          Authdatas: 0
          Times:
            Auth time: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
            Start time: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
            End time: #{Time.parse('2033-01-10 14:36:39 UTC').to_time}
            Renew Till: #{Time.parse('2033-01-10 14:36:39 UTC').to_time}
          Ticket:
            Ticket Version Number: 5
            Realm: WINDOMAIN.LOCAL
            Server Name: cifs/dc.windomain.local
            Encrypted Ticket Part:
              Ticket etype: 23 (RC4_HMAC)
              Key Version Number: 2
              Decrypted (with key: 88e4d9fabaecf3dec18dd80905521b29):
                Times:
                  Auth time: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
                  Start time: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
                  End time: #{Time.parse('2033-01-10 14:36:39 UTC').to_time}
                  Renew Till: #{Time.parse('2033-01-10 14:36:39 UTC').to_time}
                Client Addresses: 0
                Transited: tr_type: 0, Contents: ""
                Client Name: 'Administrator'
                Client Realm: 'WINDOMAIN.LOCAL'
                Ticket etype: 23 (RC4_HMAC)
                Session Key: 66383738646463363738633761643766
                Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
                PAC:
                  Validation Info:
                    Logon Time: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
                    Logoff Time: Never Expires (inf)
                    Kick Off Time: Never Expires (inf)
                    Password Last Set: No Time Set (0)
                    Password Can Change: No Time Set (0)
                    Password Must Change: Never Expires (inf)
                    Logon Count: 0
                    Bad Password Count: 0
                    User ID: 500
                    Primary Group ID: 513
                    User Flags: 0
                      .... .... .... .... ..0. .... .... .... Used Lmv2 Auth And Ntlmv2 Session Key: The USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY bit is NOT SET
                      .... .... .... .... ...0 .... .... .... Used Lmv2 Auth And Session Key: The USED_LMV2_AUTH_AND_SESSION_KEY bit is NOT SET
                      .... .... .... .... .... 0... .... .... Used Ntlmv2 Auth And Session Key: The USED_NTLMV2_AUTH_AND_SESSION_KEY bit is NOT SET
                      .... .... .... .... .... .0.. .... .... Profile Path Populated: The PROFILE_PATH_POPULATED bit is NOT SET
                      .... .... .... .... .... ..0. .... .... Resource Group Ids: The RESOURCE_GROUP_IDS bit is NOT SET
                      .... .... .... .... .... ...0 .... .... Accepts Ntlmv2: The ACCEPTS_NTLMV2 bit is NOT SET
                      .... .... .... .... .... .... 0... .... Machine Account: The MACHINE_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .0.. .... Sub Authentication: The SUB_AUTHENTICATION bit is NOT SET
                      .... .... .... .... .... .... ..0. .... Extra Sids: The EXTRA_SIDS bit is NOT SET
                      .... .... .... .... .... .... .... 0... Lan Manager: The LAN_MANAGER bit is NOT SET
                      .... .... .... .... .... .... .... ..0. No Encryption: The NO_ENCRYPTION bit is NOT SET
                      .... .... .... .... .... .... .... ...0 Guest: The GUEST bit is NOT SET
                    User Session Key: 00000000000000000000000000000000
                    User Account Control: 528
                      .... .... ..0. .... .... .... .... .... Use Aes Keys: The USE_AES_KEYS bit is NOT SET
                      .... .... ...0 .... .... .... .... .... Partial Secrets Account: The PARTIAL_SECRETS_ACCOUNT bit is NOT SET
                      .... .... .... 0... .... .... .... .... No Auth Data Required: The NO_AUTH_DATA_REQUIRED bit is NOT SET
                      .... .... .... .0.. .... .... .... .... Trusted To Authenticate For Delegation: The TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit is NOT SET
                      .... .... .... ..0. .... .... .... .... Password Expired: The PASSWORD_EXPIRED bit is NOT SET
                      .... .... .... ...0 .... .... .... .... Dont Require Preauth: The DONT_REQUIRE_PREAUTH bit is NOT SET
                      .... .... .... .... 0... .... .... .... Use Des Key Only: The USE_DES_KEY_ONLY bit is NOT SET
                      .... .... .... .... .0.. .... .... .... Not Delegated: The NOT_DELEGATED bit is NOT SET
                      .... .... .... .... ..0. .... .... .... Trusted For Delegation: The TRUSTED_FOR_DELEGATION bit is NOT SET
                      .... .... .... .... ...0 .... .... .... Smartcard Required: The SMARTCARD_REQUIRED bit is NOT SET
                      .... .... .... .... .... 0... .... .... Encrypted Test Password Allowed: The ENCRYPTED_TEST_PASSWORD_ALLOWED bit is NOT SET
                      .... .... .... .... .... .0.. .... .... Account Auto Lock: The ACCOUNT_AUTO_LOCK bit is NOT SET
                      .... .... .... .... .... ..1. .... .... Dont Expire Password: The DONT_EXPIRE_PASSWORD bit is SET
                      .... .... .... .... .... ...0 .... .... Server Trust Account: The SERVER_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... 0... .... Workstation Trust Account: The WORKSTATION_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .0.. .... Interdomain Trust Account: The INTERDOMAIN_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... ..0. .... Mns Logon Account: The MNS_LOGON_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... ...1 .... Normal Account: The NORMAL_ACCOUNT bit is SET
                      .... .... .... .... .... .... .... 0... Temp Duplicate Account: The TEMP_DUPLICATE_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .... .0.. Password Not Required: The PASSWORD_NOT_REQUIRED bit is NOT SET
                      .... .... .... .... .... .... .... ..0. Home Directory Required: The HOME_DIRECTORY_REQUIRED bit is NOT SET
                      .... .... .... .... .... .... .... ...0 Account Disabled: The ACCOUNT_DISABLED bit is NOT SET
                    Sub Auth Status: 0
                    Last Successful Interactive Logon: No Time Set (0)
                    Last Failed Interactive Logon: No Time Set (0)
                    Failed Interactive Logon Count: 0
                    Extra SID Count: 0
                    Resource Group Count: 0
                    Group Count: 5
                    Group IDs:
                      Relative ID: 513
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 512
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 520
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 518
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 519
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                    Logon Domain ID: S-1-5-21-3541430928-2051711210-1391384369
                    Effective Name: 'Administrator'
                    Full Name: ''
                    Logon Script: ''
                    Profile Path: ''
                    Home Directory: ''
                    Home Directory Drive: ''
                    Logon Server: ''
                    Logon Domain Name: 'WINDOMAIN.LOCAL'
                  Client Info:
                    Name: 'Administrator'
                    Client ID: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
                  Pac Server Checksum:
                    Signature: 1a038d8dd257a7d9b875280259ab0e4a
                  Pac Privilege Server Checksum:
                    Signature: 2f3a9e1e4fa7d3823dcb7edbdaaa8385
    EOF
    expected_output.join("\n")
  end

  let(:expected_encrypted_nthash_output) do
    expected_output = ['No decryption key provided proceeding without decryption.']
    expected_output << "#{file_format} File:#{ticket_path}"
    expected_output << <<~EOF.chomp
      Primary Principal: Administrator@WINDOMAIN.LOCAL
      Ccache version: 4

      Creds: 1
        Credential[0]:
          Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
          Client: Administrator@WINDOMAIN.LOCAL
          Ticket etype: 23 (RC4_HMAC)
          Key: 66383738646463363738633761643766
          Subkey: false
          Ticket Length: 974
          Ticket Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
          Addresses: 0
          Authdatas: 0
          Times:
            Auth time: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
            Start time: #{Time.parse('2023-01-13 14:36:39 UTC').to_time}
            End time: #{Time.parse('2033-01-10 14:36:39 UTC').to_time}
            Renew Till: #{Time.parse('2033-01-10 14:36:39 UTC').to_time}
          Ticket:
            Ticket Version Number: 5
            Realm: WINDOMAIN.LOCAL
            Server Name: cifs/dc.windomain.local
            Encrypted Ticket Part:
              Ticket etype: 23 (RC4_HMAC)
              Key Version Number: 2
              Cipher:
                j0e+dj47a5qFkMK9CmKVO2qTuat/zbSFm0gZhb274/8hwDSzZHKsrRWIH027/XFKyS+JTpv1c2+jON0zKEsLDSD8UkxL5aWs4gbOqA9Wnj/rJxBZcNd4d9OtPM1xGV2Dvr7CVHzQOHB9in20EBQGHctMz+aA874ayOWgOf+xWJORS45w/2ZwEOL+Fav3sjGFo2fbj8mNQ45p9PdNPPr1reo/jxJNlTfuGibLYN4AeHvoibYlMjk6v7qx1RSwlcQcN/ptvV4unds/I1zP06al+rjPPBZ2C1fraKFyG6cigqD/ee7ve6jm52/LR/hbRcsOQAub0OmYtElPnPS8NMEw9rl53FGT2sSOOqXzyQ4Wf/gaWyQsRebr5VU6+mx5T14n55SLLevec+XFr98kgV5iZjOrehhuZOX1TDjFL5IQ6nSq4ps9StPRRZuL6dWDXXpshRJoYf4WslAmZglEzflc/8RKZ9Fqi9XugY+yyg4jS5JsYlAhb3AcltmeuPgOBgVTa1tcDwTYOrB1c4+KVaH4VlOWDuKEkztaBeI/lci4/inpX5a2NjDACgqZI+r/+6QV6P4d0dSUSTsqdSvbruR7lGELrCX8D9dsxlpPi3tfd2E/JPLgd91nf6zYB69odF2mTuw/p/8Bc5qGqriNEVN3ofLbvlx15JNSJpXWTopwe8qy81mc0wi05ctkTRUwmWzh7Y6jBpkwBaPXQxLrLkbOynd/uumte91nC7EVO5wappLWnVkc6O0Yv/AR7KSjzjFDqDK3fwq9SeTYRW9NESskXzGOkEFw9AyoG9hw5IsV9+FYfb4My1KAcv8kqKavk42yzOMWQxw6zOUyTcVPgkHfZAzosbP5bl2kkCIkmWUiS8E37qQ9Na9ieHXnaGW0oCQ76wxKXo7xKTTFcwF72TbtkKmQ20rvtC/DmteyTh4aaLFFjZhvH4hnBk4ukjOSi16rqlcZuXfhOtvBZqWtqrtsR6ir1edl48+ir33Ljs1jTGpdR47IkJMxcABQ5EExwORtW5VJj4m1tOrJYMQ6ShZpPCl62fT/hLD6qaqsR7GkmGTkw6omEJw4j2DrKfoV50vkObTtE4dLkY+JvgwBExn377yTI/zqPLPXvA4Atae/BnOtW3kSFxc/woBqD2mwEklWwuO9aXeCdTCjx5YG7g==
    EOF
    expected_output.join("\n")
  end

  context 'with ccache (aes key)' do
    let(:ticket_path) { ccache_file_aes.path }
    let(:file_format) { 'Credentials cache:' }
    let(:key_type) { 'AES_KEY' }
    let(:key) { aes_key }
    let(:invalid_key_error_msg) { "bad-config: AES key length was #{invalid_key.size}. It should be 32 or 64" }
    let(:expected_decrypted_output) { expected_decrypted_aes_output }
    let(:expected_encrypted_output) { expected_encrypted_aes_output }

    it_behaves_like 'inspect ticket'
  end

  context 'with kirbi (aes key)' do
    let(:ticket_path) { kirbi_file_aes.path }
    let(:file_format) { 'Kirbi' }
    let(:key_type) { 'AES_KEY' }
    let(:key) { aes_key }
    let(:invalid_key_error_msg) { "bad-config: AES key length was #{invalid_key.size}. It should be 32 or 64" }
    let(:expected_decrypted_output) { expected_decrypted_aes_output }
    let(:expected_encrypted_output) { expected_encrypted_aes_output }

    it_behaves_like 'inspect ticket'
  end

  context 'with ccache (nthash)' do
    let(:ticket_path) { ccache_file_nthash.path }
    let(:file_format) { 'Credentials cache:' }
    let(:key_type) { 'NTHASH' }
    let(:key) { nthash }
    let(:invalid_key_error_msg) { "bad-config: NTHASH length was #{invalid_key.size}. It should be 32" }
    let(:expected_decrypted_output) { expected_decrypted_nthash_output }
    let(:expected_encrypted_output) { expected_encrypted_nthash_output }

    it_behaves_like 'inspect ticket'
  end

  context 'with kirbi (nthash)' do
    let(:ticket_path) { kirbi_file_nthash.path }
    let(:file_format) { 'Kirbi' }
    let(:key_type) { 'NTHASH' }
    let(:key) { nthash }
    let(:invalid_key_error_msg) { "bad-config: NTHASH length was #{invalid_key.size}. It should be 32" }
    let(:expected_decrypted_output) { expected_decrypted_nthash_output }
    let(:expected_encrypted_output) { expected_encrypted_nthash_output }

    it_behaves_like 'inspect ticket'
  end
end
