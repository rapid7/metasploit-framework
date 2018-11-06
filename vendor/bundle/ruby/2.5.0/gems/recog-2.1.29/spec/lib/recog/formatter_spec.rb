require 'recog/formatter'

describe Recog::Formatter do
  let(:output) { StringIO.new }

  context "with no color" do
    subject { Recog::Formatter.new(double(color: false), output) }

    describe "#message" do
      it "outputs the text" do
        subject.status_message 'some text'
        expect(output.string).to eq("some text\n")
      end
    end

    describe "#success_message" do
      it "outputs the text" do
        subject.success_message 'a success'
        expect(output.string).to eq("a success\n")
      end
    end

    describe "#warning_message" do
      it "outputs the text" do
        subject.warning_message 'a warning'
        expect(output.string).to eq("a warning\n")
      end
    end

    describe "#failure_message" do
      it "outputs the text" do
        subject.failure_message 'a failure'
        expect(output.string).to eq("a failure\n")
      end
    end
  end

  context "with color" do
    subject { Recog::Formatter.new(double(color: true), output) }

    describe "#message" do
      it "outputs the text in white" do
        subject.status_message 'some text'
        expect(output.string).to eq("\e[15msome text\e[0m\n")
      end
    end

    describe "#success_message" do
      it "outputs the text in green" do
        subject.success_message 'a success'
        expect(output.string).to eq("\e[32ma success\e[0m\n")
      end
    end

    describe "#warning_message" do
      it "outputs the text in yellow" do
        subject.warning_message 'a warning'
        expect(output.string).to eq("\e[33ma warning\e[0m\n")
      end
    end

    describe "#failure_message" do
      it "outputs the text in red" do
        subject.failure_message 'a failure'
        expect(output.string).to eq("\e[31ma failure\e[0m\n")
      end
    end
  end
end
