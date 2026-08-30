RSpec.describe Rex::Proto::MsTds::MsTdsLogin7 do
  context 'when in its default state' do
    let(:instance) { described_class.new }

    describe '#tds_version' do
      it 'defaults to version 7.1' do
        expect(instance.tds_version).to eq Rex::Proto::MsTds::MsTdsVersion::VERSION_7_1
      end

      it 'is a MsTdsVersion instance' do
        expect(instance.tds_version).to be_a Rex::Proto::MsTds::MsTdsVersion
      end
    end

    describe '#client_prog_ver' do
      it 'defaults to version 7' do
        expect(instance.client_prog_ver).to eq 7
      end
    end

    describe '#option_flags_1' do
      describe '#f_set_lang' do
        it 'defaults to 1' do
          expect(instance.option_flags_1.f_set_lang).to eq 1
        end
      end

      describe '#f_database' do
        it 'defaults to 0' do
          expect(instance.option_flags_1.f_database).to eq 0
        end
      end

      describe '#f_use_db' do
        it 'defaults to 1' do
          expect(instance.option_flags_1.f_use_db).to eq 1
        end
      end
    end

    describe '#option_flags_2' do
      describe '#f_int_security' do
        it 'defaults to 0' do
          expect(instance.option_flags_2.f_int_security).to eq 0
        end
      end

      describe '#f_odbc' do
        it 'defaults to 1' do
          expect(instance.option_flags_2.f_odbc).to eq 1
        end
      end
    end

    describe '#server_name' do
      it 'defaults to a random value' do
        expect(instance.server_name).to be_a RubySMB::Field::String16
        expect(instance.server_name.value).to_not be_empty
      end

      it 'equals the hostname' do
        expect(instance.server_name).to eq instance.hostname
      end
    end

    describe '#hostname' do
      it 'defaults to a random value' do
        expect(instance.hostname).to be_a RubySMB::Field::String16
        expect(instance.hostname.value).to_not be_empty
      end

      it 'equals the server name' do
        expect(instance.hostname).to eq instance.server_name
      end
    end

    describe '#clt_int_name' do
      it 'defaults to a random value' do
        expect(instance.clt_int_name).to be_a RubySMB::Field::String16
        expect(instance.clt_int_name.value).to_not be_empty
      end

      it 'equals the server name' do
        expect(instance.app_name).to eq instance.clt_int_name
      end
    end

    describe '#app_name' do
      it 'defaults to a random value' do
        expect(instance.app_name).to be_a RubySMB::Field::String16
        expect(instance.app_name.value).to_not be_empty
      end

      it 'equals the server name' do
        expect(instance.app_name).to eq instance.clt_int_name
      end
    end

    describe '#username' do
      it 'defaults to nil' do
        expect(instance.username).to be_nil
      end
    end

    describe '#password' do
      it 'defaults to nil' do
        expect(instance.password).to be_nil
      end
    end

    describe '#language' do
      it 'defaults to an empty string' do
        expect(instance.language).to be_a RubySMB::Field::String16
        expect(instance.language.value).to eq ''
      end
    end

    describe '#database' do
      it 'defaults to an empty string' do
        expect(instance.database).to be_a RubySMB::Field::String16
        expect(instance.database.value).to eq ''
      end
    end

    describe '#client_id' do
      it 'defaults to a random value' do
        expect(instance.client_id).to be_a BinData::Uint8Array
        expect(instance.client_id.length).to eq 6
      end
    end
  end

  context 'when initialized with a buffer field' do
    let(:hostname) { Rex::Text.rand_text_alphanumeric(8).encode(Encoding::UTF_16LE) }
    let(:instance) { described_class.new(hostname: hostname) }

    describe '#hostname' do
      it 'defaults to hostname' do
        expect(instance.hostname).to be_a RubySMB::Field::String16
        expect(instance.hostname.value).to eq hostname
      end
    end
  end

  describe '.read' do
    context 'when the buffer field is empty' do
      let(:instance) { described_class.read([ 86, 0x71000000 ].pack('VV') + ("\x00".b * 78)) }

      describe "#hostname" do
        it 'sets it to nil' do
          expect(instance.hostname).to be_nil
        end
      end

      describe "#username" do
        it 'sets it to nil' do
          expect(instance.username).to be_nil
        end
      end

      describe "#password" do
        it 'sets it to nil' do
          expect(instance.password).to be_nil
        end
      end

      describe "#app_name" do
        it 'sets it to nil' do
          expect(instance.app_name).to be_nil
        end
      end

      describe "#server_name" do
        it 'sets it to nil' do
          expect(instance.server_name).to be_nil
        end
      end

      describe "#unused" do
        it 'sets it to nil' do
          expect(instance.unused).to be_nil
        end
      end

      describe "#extension" do
        it 'sets it to nil' do
          expect(instance.extension).to be_nil
        end
      end

      describe "#clt_int_name" do
        it 'sets it to nil' do
          expect(instance.clt_int_name).to be_nil
        end
      end

      describe "#language" do
        it 'sets it to nil' do
          expect(instance.language).to be_nil
        end
      end

      describe "#database" do
        it 'sets it to nil' do
          expect(instance.database).to be_nil
        end
      end

      describe "#sspi" do
        it 'sets it to nil' do
          expect(instance.sspi).to be_nil
        end
      end

      describe "#attach_db_file" do
        it 'sets it to nil' do
          expect(instance.attach_db_file).to be_nil
        end
      end

      describe "#change_password" do
        it 'sets it to nil' do
          expect(instance.change_password).to be_nil
        end
      end
    end

    context 'when the buffer field is populated' do
      context 'with fields in their natural order' do
        let(:instance) do
          described_class.read([
            [ 118, 0x71000000 ].pack('VV') + ("\x00".b * 32),
              [ 86, 8 ].pack('vv') ,
              [ 102, 8 ].pack('vv'),
              ("\x00".b * 38),
              'username'.encode(Encoding::UTF_16LE).force_encoding(Encoding::ASCII_8BIT),
              'password'.encode(Encoding::UTF_16LE).force_encoding(Encoding::ASCII_8BIT)
          ].join)
        end

        describe '#username' do
          it 'is read correctly' do
            expect(instance.username).to eq 'username'.encode(Encoding::UTF_16LE)
          end
        end

        describe '#password' do
          it 'is read correctly' do
            expect(instance.password).to eq 'password'.encode(Encoding::UTF_16LE)
          end
        end
      end

      context 'with fields in their reversed order' do
        # test that buffer field order doesn't matter when reading, this is important for parity with the spec
        let(:instance) do
          described_class.read([
            [ 118, 0x71000000 ].pack('VV') + ("\x00".b * 32),
              [ 102, 8 ].pack('vv'),
              [ 86, 8 ].pack('vv') ,
              ("\x00".b * 38),
              'password'.encode(Encoding::UTF_16LE).force_encoding(Encoding::ASCII_8BIT),
              'username'.encode(Encoding::UTF_16LE).force_encoding(Encoding::ASCII_8BIT),
          ].join)
        end

        describe '#username' do
          it 'is read correctly' do
            expect(instance.username).to eq 'username'.encode(Encoding::UTF_16LE)
          end
        end

        describe '#password' do
          it 'is read correctly' do
            expect(instance.password).to eq 'password'.encode(Encoding::UTF_16LE)
          end
        end
      end
    end
  end
end