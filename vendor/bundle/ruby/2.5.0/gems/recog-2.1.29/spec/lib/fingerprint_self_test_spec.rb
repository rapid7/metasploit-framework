require 'recog/db'
require 'regexp_parser'
require 'nokogiri'

describe Recog::DB do
  let(:schema) { Nokogiri::XML::Schema(open(File.expand_path(File.join(%w(xml fingerprints.xsd))))) }
  Dir[File.expand_path File.join('xml', '*.xml')].each do |xml_file_name|

    describe "##{File.basename(xml_file_name)}" do

      it "is valid XML" do
        doc = Nokogiri::XML(open(xml_file_name))
        errors = schema.validate(doc)
        expect(errors).to be_empty, "#{xml_file_name} is invalid recog XML -- #{errors.inspect}"
      end

      db = Recog::DB.new(xml_file_name)

      it "has a match key" do
        expect(db.match_key).not_to be_nil
        expect(db.match_key).not_to be_empty
      end

      it "has valid 'preference' value" do
          # Reserve values below 0.10 and above 0.90 for users
          # See xml/fingerprints.xsd
          expect(db.preference.class).to be ::Float
          expect(db.preference).to be_between(0.10, 0.90)
      end

      db.fingerprints.each_index do |i|
        fp = db.fingerprints[i]

        context "#{fp.name}" do
          param_names = []
          fp.params.each do |param_name, pos_value|
            pos, value = pos_value
            it "has valid looking fingerprint parameter names" do
              unless param_name =~ /^(?:cookie|[^\.]+\..*)$/
                fail "'#{param_name}' is invalid"
              end
            end

            it "doesn't have param values for capture params" do
              if pos > 0 && !value.to_s.empty?
                fail "'#{fp.name}'s #{param_name} is a non-zero pos but specifies a value of '#{value}'"
              end
            end

            it "doesn't omit values for non-capture params" do
              if pos == 0 && value.to_s.empty?
                fail "'#{fp.name}'s #{param_name} is not a capture (pos=0) but doesn't specify a value"
              end
            end

            it "doesn't have duplicate params" do
              if param_names.include?(param_name)
                fail "'#{fp.name}'s has duplicate #{param_name}"
              else
                param_names << param_name
              end
            end

            it "uses interpolation correctly" do
              if pos == 0 && /\{(?<interpolated>[^\s{}]+)\}/ =~ value
                unless fp.params.key?(interpolated)
                  fail "'#{fp.name}' uses interpolated value '#{interpolated}' that does not exist"
                end
              end
            end
          end
        end

        context "#{fp.regex}" do

          it "has a valid looking name" do
            expect(fp.name).not_to be_nil
            expect(fp.name).not_to be_empty
          end

          it "has a regex" do
            expect(fp.regex).not_to be_nil
            expect(fp.regex.class).to be ::Regexp
          end

          it 'uses capturing regular expressions properly' do
            # the list of index-based captures that the fingerprint is expecting
            expected_capture_positions = fp.params.values.map(&:first).map(&:to_i).select { |position| position > 0 }
            if fp.params.empty? && expected_capture_positions.size > 0
              fail "Non-asserting fingerprint with regex #{fp.regex} captures #{expected_capture_positions.size} time(s); 0 are needed"
            else
              # parse the regex and count the number of captures
              actual_capture_positions = []
              capture_number = 1
              Regexp::Scanner.scan(fp.regex).each do |token_parts|
                if token_parts.first == :group  && ![:close, :passive, :options].include?(token_parts[1])
                  actual_capture_positions << capture_number
                  capture_number += 1
                end
              end
              # compare the captures actually performed to those being used and ensure that they contain
              # the same elements regardless of order, preventing, over-, under- and other forms of mis-capturing.
              actual_capture_positions = actual_capture_positions.sort.uniq
              expected_capture_positions = expected_capture_positions.sort.uniq
              expect(actual_capture_positions).to eq(expected_capture_positions),
                "Regex has #{actual_capture_positions.size} capture groups, but the fingerprint expected #{expected_capture_positions.size} extractions."
            end
          end

          # Not yet enforced
          # it "has test cases" do
          #  expect(fp.tests.length).not_to equal(0)
          # end

          it "Has a reasonable number (<= 20) of test cases" do
            expect(fp.tests.length).to be <= 20
          end

          fp.tests.each do |example|
            it "Example '#{example.content}' matches this regex" do
              match = fp.match(example.content)
              expect(match).to_not be_nil, 'Regex did not match'
              # test any extractions specified in the example
              example.attributes.each_pair do |k,v|
                next if k == '_encoding'
                expect(match[k]).to eq(v), "Regex didn't extract expected value for fingerprint attribute #{k} -- got #{match[k]} instead of #{v}"
              end
            end

            it "Example '#{example.content}' matches this regex first" do
              db.fingerprints.slice(0, i).each_index do |previous_i|
                prev_fp = db.fingerprints[previous_i]
                prev_fp.tests.each do |prev_example|
                  match = prev_fp.match(example.content)
                  expect(match).to be_nil, "Matched regex ##{previous_i} (#{db.fingerprints[previous_i].regex}) rather than ##{i} (#{db.fingerprints[i].regex})"
                end
              end
            end
          end

        end
      end

    end
  end
end
