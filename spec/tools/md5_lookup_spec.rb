load Metasploit::Framework.root.join('tools/password/md5_lookup.rb').to_path
require 'spec_helper'

require 'rex/proto/http/response'
require 'stringio'

RSpec.describe Md5LookupUtility do

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


  describe Md5LookupUtility::Disclaimer do

    let(:group_name)   { 'MD5Lookup' }
    let(:setting_name) { 'waiver' }
    let(:data)         { true }
    let(:t_path)       { 'filepath' }

    def stub_save
      ini = Rex::Parser::Ini.new(t_path)
      allow(ini).to receive(:to_file).with(any_args)
      allow(Rex::Parser::Ini).to receive(:new).and_return(ini)
      return ini
    end

    def stub_load(with_setting=true)
      if with_setting
        ini = stub_save
        disclamer.save_waiver
      else
        ini = Rex::Parser::Ini.new(t_path)
      end

      allow(Rex::Parser::Ini).to receive(:new).and_return(ini)
      return ini
    end

    subject(:disclamer) do
      Md5LookupUtility::Disclaimer.new
    end

    describe '#ack' do
      context 'When \'Y\' is entered' do
        it 'returns true' do
          agree = "Y\n"
          allow($stdin).to receive(:gets).and_return(agree)
          get_stdout { expect(disclamer.ack).to be_truthy }
        end
      end
    end

    describe '#save_waiver' do
      context 'when waiver is true' do
        it 'saves the wavier setting' do
          ini = stub_save
          disclamer.save_waiver
          expect(ini[group_name]).to eq({setting_name=>true})
        end
      end
    end

    describe '#has_waiver?' do
      context 'when there is a waiver' do
        it 'returns true' do
          ini = stub_load(true)
          expect(disclamer.send(:has_waiver?)).to be_truthy
        end
      end

      context 'when there is no waiver' do
        it 'returns false' do
          ini = stub_load(false)
          expect(disclamer.send(:has_waiver?)).to be_falsey
        end
      end
    end

    describe '#save_setting' do
      context 'when a setting is given' do
        it 'saves the setting' do
          ini = stub_save
          disclamer.send(:save_setting, setting_name, data)
          expect(ini[group_name]).to eq({setting_name=>true})
        end
      end
    end

    describe '#load_setting' do
    end

  end


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

    before(:example) do
      expect(Md5LookupUtility::OptsConsole).to receive(:parse).with(any_args).and_return(options)
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
        it 'prints a \'found\' message' do
          disclaimer = Md5LookupUtility::Disclaimer.new
          allow(disclaimer).to receive(:has_waiver?).and_return(true)
          allow(Md5LookupUtility::Disclaimer).to receive(:new).and_return(disclaimer)
          allow(subject).to receive(:get_hash_results).and_yield(expected_result)
          output = get_stdout { subject.run }
          expect(output).to include('Found:')
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
    let(:valid_argv) { "-i #{input_file} -d all -o #{output_file}".split }

    let(:invalid_argv) { "".split }

    subject do
      Md5LookupUtility::OptsConsole
    end

    describe '.parse' do
      context 'when valid arguments are passed' do
        let(:opts) { subject.parse(valid_argv) }

        before(:example) do
          allow(File).to receive(:exist?).and_return(true)
        end

        it 'returns the input file path' do
          expect(opts[:input]).to eq(input_file)
        end

        it 'returns the output file path' do
          expect(opts[:outfile]).to eq(output_file)
        end

        it 'returns the databases in an array' do
          expect(opts[:databases]).to be_a(Array)
          expect(opts[:databases]).to include(db_source)
        end
      end

      context 'when the required input file is not set' do
        before(:example) do
          allow(File).to receive(:exist?).and_return(false)
        end

        it 'raises an OptionParser::MissingArgument error' do
          expect{subject.parse(invalid_argv)}.to raise_error(OptionParser::MissingArgument)
        end
      end

    end


    describe '.extract_db_names' do
      let(:list) {'i337,invalid'}
      context 'when database symbols \'i337\' and \'invalid\' are given' do
        it 'returns i337.net in an array' do
          db_names = subject.extract_db_names(list)
          expect(db_names).to be_a(Array)
          expect(db_names).to include(db_source)
        end
      end
    end

    describe '.get_database_symbols' do
      it 'returns an array' do
        expect(subject.get_database_symbols).to be_a(Array)
      end
    end

    describe '.get_database_names' do
      it 'returns an array' do
        expect(subject.get_database_names).to be_a(Array)
      end
    end
  end

end
