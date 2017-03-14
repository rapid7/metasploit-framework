RSpec.shared_examples_for "Rex::ImageSource::ImageSource" do

  describe "#read_asciiz" do
    let(:offset) { 0 }

    it "returns an String" do
      expect(subject.read_asciiz(offset)).to be_kind_of(String)
    end

    it "returns a null free String" do
      expect(subject.read_asciiz(offset)).to_not include("\x00")
    end

    context "when offset bigger than available data" do
      let(:offset) { 12345678 }

      it "returns an empty String" do
        expect(subject.read_asciiz(offset)).to be_empty
      end
    end
  end

end
