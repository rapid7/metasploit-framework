require 'nokogiri'
require 'recog/fingerprint'

describe Recog::Fingerprint do
  context "whitespace" do
    let(:xml) do
      path = File.expand_path(File.join('spec', 'data', 'whitespaced_fingerprint.xml'))
      doc = Nokogiri::XML(IO.read(path))
      doc.xpath("//fingerprint").first
    end
    subject { Recog::Fingerprint.new(xml) }

    describe "#name" do
      it "properly squashes whitespace" do
        expect(subject.name).to eq('I love whitespace!')
      end
    end
  end

  skip  "value interpolation" do
    # TODO
  end
end
