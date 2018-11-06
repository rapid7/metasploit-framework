require 'recog'
require 'yaml'


VALID_FILTER = {match_key: 'smb.native_os', protocol: 'smb', database_type: 'util.os'}
NOMATCH_MATCH_KEY = {match_key: 'no_such_987', protocol: 'smb', database_type: 'util.os'}
NOMATCH_PROTO = {match_key: 'smb.native_os', protocol: 'no_such_987', database_type: 'util.os'}
NOMATCH_TYPE = {match_key: 'smb.native_os', protocol: 'smb', database_type: 'no_such_987'}

describe Recog::Nizer do
  subject { described_class }

  describe ".match" do
    File.readlines(File.expand_path(File.join('spec', 'data', 'smb_native_os.txt'))).each do |line|
      data = line.strip
      context "with smb_native_os:#{data}" do
        let(:match_result) { subject.match('smb.native_os', data) }

        it "returns a hash" do
          expect(match_result.class).to eq(::Hash)
        end

        it "returns a successful match" do
          expect(match_result['matched'].to_s).to match(/^[A-Z]/)
        end

        it "correctly matches service or os" do
          if data =~ /^Windows/
            expect(match_result['os.product']).to match(/^Windows/)
          end
        end

        let(:nomatch_result) { subject.match('smb.native_os', 'no_such_987_76tgklh') }
        it "returns a nil when data cannot be matched" do
          expect(nomatch_result).to be_nil
        end

        let(:invalid_db_result) { subject.match('no_such_987', data) }
        it "returns a nil when match_key search doesn't match" do
          expect(invalid_db_result).to be_nil
        end
      end
    end

    line = 'non-existent'
    context "with non-existent match" do
      let(:match_result) {subject.match('smb.native_os', line) }
      it "returns a nil" do
        expect(match_result).to be_nil
      end
    end
  end

  describe ".match_all_db" do
    File.readlines(File.expand_path(File.join('spec', 'data', 'smb_native_os.txt'))).each do |line|
      data = line.strip
      context "with smb_native_os:#{data}" do
        let(:match_all_result) { subject.match_all_db(data, VALID_FILTER) }

        it "returns an array" do
          expect(match_all_result.class).to eq(::Array)
        end

        it "returns a successful match" do
          expect(match_all_result[0]['matched']).to match(/^[A-Z]/)
        end

        it "correctly matches service or os" do
          if data =~ /^Windows/
            expect(match_all_result[0]['os.product']).to match(/^Windows/)
          end
        end

        it "correctly matches protocol" do
          expect(match_all_result[0]['service.protocol']).to eq('smb')
        end

        let(:no_filter_result) { subject.match_all_db(data) }
        it "returns an array when searching without a filter" do
          expect(no_filter_result.class).to eq(::Array)
        end

        it "returns a successful match when searching without a filter" do
          expect(no_filter_result[0]['matched']).to match(/^[A-Z]/)
        end

        it "correctly matches service or os when searching without a filter" do
          if data =~ /^Windows/
            expect(no_filter_result[0]['os.product']).to match(/^Windows/)
          end
        end

        let(:nomatch_db_result) { subject.match_all_db(data, NOMATCH_MATCH_KEY) }
        it "returns an array when match_key search doesn't match" do
          expect(nomatch_db_result.class).to eq(::Array)
        end
        it "returns an empty array when match_key search doesn't match" do
          expect(nomatch_db_result).to be_empty
        end

        let(:nomatch_proto_result) { subject.match_all_db(data, NOMATCH_PROTO) }
        it "returns an array when protocol search doesn't match" do
          expect(nomatch_proto_result.class).to eq(::Array)
        end
        it "returns an empty array when protocol search doesn't match" do
          expect(nomatch_proto_result).to be_empty
        end

        let(:nomatch_type_result) { subject.match_all_db(data, NOMATCH_TYPE) }
        it "returns an array when database_type search doesn't match" do
          expect(nomatch_type_result.class).to eq(::Array)
        end
        it "returns an empty array when database_type search doesn't match" do
          expect(nomatch_proto_result).to be_empty
        end
      end
    end

    line = 'non-existent'
    context "with non-existent match" do
      let(:match_result) {subject.match_all_db(line) }
      it "returns an array" do
        expect(match_result.class).to eq(::Array)
      end
      it "returns an empty array" do
        expect(match_result).to be_empty
      end
    end
  end

  describe ".multi_match" do
    File.readlines(File.expand_path(File.join('spec', 'data', 'smb_native_os.txt'))).each do |line|
      data = line.strip

      context "with smb_native_os:#{data}" do
        let(:match_results) {subject.multi_match('smb.native_os', data) }

        it "returns an array" do
          expect(match_results.class).to eq(::Array)
        end

        it "returns at least one successful match" do
          expect(match_results.size).to be > 0
        end

        it "correctly matches service or os" do
          match_results do |mr|
            if data =~ /^Windows/
              expect(mr['os.product']).to match(/^Windows/)
            end
          end
        end

        let(:invalid_db_result) { subject.multi_match('no_such_987', data) }
        it "returns an array when passed an invalid match_key" do
          expect(invalid_db_result.class).to eq(::Array)
        end

        it "returns an empty array when passed an invalid match_key" do
          expect(invalid_db_result).to be_empty
        end
      end

    end

    data = 'Windows Server 2012 R2 Standard 9600'
    context "with {data}" do
      let(:match_results) {subject.multi_match('smb.native_os', data) }

      it "returns an array" do
        expect(match_results.class).to eq(::Array)
      end

      it "returns at least two successful matches" do
        expect(match_results.size).to be > 1
      end

      it "correctly matches os.product for all matches" do
        match_results do |mr|
          if data =~ /^Windows/
            expect(mr['os.product']).to match(/^Windows/)
          end
        end
      end

      it "correctly matches protocol for all matches" do
        match_results do |mr|
          if data =~ /^Windows/
            expect(mr['service.protocol']).to eq('smb')
          end
        end
      end
    end

    line = 'non-existent'
    context "with non-existent match" do
      let(:match_results) {subject.multi_match('smb.native_os', line) }

      it "returns an array" do
        expect(match_results.class).to eq(::Array)
      end

      it "returns an empty array" do
        expect(match_results).to be_empty
      end
    end
  end

  describe ".best_os_match" do
    # Demonstrates how this method picks up additional attributes from other members of the winning
    # os.product match group and applies them to the result.
    matches1 = YAML.load(File.read(File.expand_path(File.join('spec', 'data', 'best_os_match_1.yml'))))
    context "with best_os_match_1.yml" do
      let(:result) { subject.best_os_match(matches1) }

      it "returns a hash" do
        expect(result.class).to eq(::Hash)
      end

      it "matches Windows 2008" do
        expect(result['os.product']).to eq('Windows 2008')
      end

      it "matches Microsoft" do
        expect(result['os.vendor']).to eq('Microsoft')
      end

      it "matches English" do
        expect(result['os.language']).to eq('English')
      end

      it "matches service pack 2" do
        expect(result['os.version']).to eq('Service Pack 2')
      end
    end

    # Demonstrates how additive os.certainty values allow a 1.0 certainty rule to be overridden
    # by multiple lower certainty matches
    matches2 = YAML.load(File.read(File.expand_path(File.join('spec', 'data', 'best_os_match_2.yml'))))
    context "with best_os_match_2.yml" do
      let(:result) { subject.best_os_match(matches2) }

      it "returns a hash" do
        expect(result.class).to eq(::Hash)
      end

      it "matches Windows 2012" do
        expect(result['os.product']).to eq('Windows 2012')
      end

      it "matches Microsoft" do
        expect(result['os.vendor']).to eq('Microsoft')
      end

      it "matches Arabic" do
        expect(result['os.language']).to eq('Arabic')
      end

      it "matches service pack 1" do
        expect(result['os.version']).to eq('Service Pack 1')
      end
    end

  end

  describe ".best_service_match" do
    # Demonstrates how this method picks up additional attributes from other members of the winning
    # service.product match group and applies them to the result.
    matches1 = YAML.load(File.read(File.expand_path(File.join('spec', 'data', 'best_service_match_1.yml'))))
    context "with best_service_match_1.yml" do
      let(:result) { subject.best_service_match(matches1) }

      it "returns a hash" do
        expect(result.class).to eq(::Hash)
      end

      it "matches IIS" do
        expect(result['service.product']).to eq('IIS')
      end

      it "matches Microsoft" do
        expect(result['service.vendor']).to eq('Microsoft')
      end

      it "matches English" do
        expect(result['service.language']).to eq('English')
      end

      it "matches version 6.0" do
        expect(result['service.version'].to_i).to eq(6.0)
      end
    end

  end


  describe '.load_db' do
    file_path = File.expand_path(File.join('spec', 'data', 'test_fingerprints.xml'))
    context "with #{file_path}" do
      let(:fp_db) { subject.load_db(file_path) }
      it "loads without error" do
        expect(fp_db).to  be true
        subject.unload_db()
      end
    end

    context "with no path specified" do
      let(:fp_db) { subject.load_db }
      it "loads without error" do
        expect(fp_db).to  be true
        subject.unload_db()
      end
    end

    context "with empty file path" do
      it "raises an error" do
        expect { subject.load_db('') }.to raise_error(Errno::ENOENT)
        subject.unload_db()
      end
    end

    context "with invalid file path" do
      it "raises an error" do
        expect { subject.load_db('no_such_987_file_path') }.to raise_error(Errno::ENOENT)
        subject.unload_db()
      end
    end
  end

end
