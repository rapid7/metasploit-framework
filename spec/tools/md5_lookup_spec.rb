load Metasploit::Framework.root.join('tools/md5_lookup.rb').to_path

require 'rex/proto/http/response'
require 'stringio'

describe Md5LookupUtility do

  #
  # Init some data
  #

  let(:input_data) do
    '098f6bcd4621d373cade4e832627b4f6'
  end

  let(:bad_input_data) do
    ''
  end

  let(:good_result) do
    'test'
  end

  let(:empty_result) do
    ''
  end

  let(:good_json_response) do
    %Q|{ "status":true, "result":"test", "message":"" }|
  end

  let(:bad_json_response) do
    %Q|{ "status":false, "result":"", "message":"not found" }|
  end

  let(:db_source) do
    'i337.net'
  end

  let(:input_file) do
    'input.txt'
  end

  let(:output_file) do
    'output.txt'
  end

  let(:options) do
    {
      :databases => [db_source],
      :outfile   => output_file,
      :input     => input_file
    }
  end

  before(:each) do
    Md5LookupUtility::OptsConsole.stub(:parse).with(any_args).and_return(options)
  end

  subject do
    Md5LookupUtility::Md5Lookup.new
  end

  def set_expected_response(body)
    res = Rex::Proto::Http::Response.new
    res.code = 200
    res.body = body
    res
  end

  def set_send_request_cgi(body)
    allow(subject).to receive(:send_request_cgi) do |opts|
      set_expected_response(body)
    end
  end

  #
  # Tests start here
  #

  describe Md5LookupUtility::Md5Lookup do

    describe '.new' do
      it 'returns a Md5LookupUtility::Md5Lookup instance' do
        expect(subject).to be_a(Md5LookupUtility::Md5Lookup)
      end
    end

    describe '#lookup' do

      context 'when a hash is found' do
        it 'returns the cracked result' do
          set_send_request_cgi(good_json_response)
          expect(subject.lookup(input_data, db_source)).to eq(good_result)
        end
      end

      context 'when a hash is not found' do
        it 'returns an empty result' do
          set_send_request_cgi(bad_json_response)
          expect(subject.lookup(input_data, db_source)).to eq(empty_result)
        end
      end
    end

    describe '#get_json_results' do
      context 'when JSON contains the found result' do
        it 'returns the cracked result' do
          res = set_expected_response(good_json_response)
          expect(subject.send(:get_json_result, res)).to eq(good_result)
        end
      end

      context 'when there is no JSON data' do
        it 'returns an empty result' do
          res = set_expected_response('')
          expect(subject.send(:get_json_result, res)).to eq(empty_result)
        end
      end
    end

  end


  describe Md5LookupUtility::Driver do

    let(:expected_result) {
      {
        :hash         => input_data,
        :cracked_hash => good_result,
        :credit       => db_source
      }
    }

    before(:each) do
      allow(File).to receive(:open).with(input_file, 'rb').and_yield(StringIO.new(input_data))
      allow(File).to receive(:new).with(output_file, 'wb').and_return(StringIO.new)
    end

    subject do
      Md5LookupUtility::Driver.new
    end

    describe '.new' do
      it 'returns a Md5LookupUtility::Driver instance' do
        expect(subject).to be_a(Md5LookupUtility::Driver)
      end
    end

    describe '#run' do
      context 'when a hash is found' do

        def get_stdout(&block)
          out = $stdout
          $stdout = fake = StringIO.new
          begin
            yield
          ensure
            $stdout = out
          end
          fake.string
        end

        it 'prints a \'found\' message' do
          allow(subject).to receive(:get_hash_results).and_yield(expected_result)
          output = get_stdout { subject.run }
          expect (output).should include('Found:')
        end
      end
    end

    describe '#save_result' do
      context 'when a result is given' do
        it 'writes the result to file' do
          subject.send(:save_result, expected_result)
          expect(subject.instance_variable_get(:@output_handle).string).to include(good_result)
        end
      end
    end

    describe '#get_hash_results' do
      context 'when a hash is found' do
        it 'yields a result' do
          search_engine = Md5LookupUtility::Md5Lookup.new
          allow(search_engine).to receive(:lookup).and_return(good_result)
          allow(Md5LookupUtility::Md5Lookup).to receive(:new).and_return(search_engine)

          expect{ |b| subject.send(:get_hash_results, input_file, [db_source], &b) }.to yield_with_args(expected_result)
        end
      end
    end

    describe '#extract_hashes' do
      context 'when a MD5 file is supplied' do
        it 'yields the MD5 hash' do
          expect{ |b| subject.send(:extract_hashes, input_file, &b) }.to yield_with_args(input_data)
        end
      end

      context 'when an empty file is supplied' do
        before do
          allow(File).to receive(:open).with(input_file, 'rb').and_yield(StringIO.new(''))
        end

        it 'yields nothing' do
          expect{ |b| subject.send(:extract_hashes, input_file, &b) }.not_to yield_control
        end
      end
    end

    describe '#is_md5_format?' do
      context 'when a valid MD5 is given' do
        it 'returns true' do
          expect(subject.send(:is_md5_format?,input_data)).to be_truthy
        end
      end

      context 'when a non-MD5 value is given' do
        it 'returns false' do
          expect(subject.send(:is_md5_format?, bad_input_data)).to be_falsey
        end
      end
    end

  end


  describe Md5LookupUtility::OptsConsole do
    let(:argv) {}

    describe '.parse' do

    end

    describe '.get_parsed_options' do
    end

    describe '.extract_db_names' do
    end

    describe '.get_database_symbols' do
    end

    describe '.get_database_names' do
    end
  end

end
