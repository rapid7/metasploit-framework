require 'recog/match_reporter'

describe Recog::MatchReporter do
  let(:options) { double(detail: false, quiet: false) }
  let(:formatter) { double('formatter').as_null_object }
  subject { Recog::MatchReporter.new(options, formatter) }

  def run_report
    subject.report do
        subject.increment_line_count
        subject.match 'a match'
        subject.failure 'a failure'
    end
  end

  describe "#report" do
    it "prints matches" do
      expect(formatter).to receive(:success_message).with('a match')
      run_report
    end

    it "prints failures" do
      expect(formatter).to receive(:failure_message).with('a failure')
      run_report
    end

    context "with detail" do
      subject { Recog::MatchReporter.new(double(detail: true, quiet: false), formatter) }

      it "prints the lines processed" do
        expect(formatter).to receive(:status_message).with("\nProcessed 1 lines")
        run_report
      end

      it "prints summary" do
        expect(formatter).to receive(:failure_message).with("SUMMARY: 1 matches and 1 failures")
        run_report
      end
    end
  end

  describe "#print_summary" do
    context "with all matches" do
      before { subject.match 'match' }

      it "prints a successful summary" do
        msg = "SUMMARY: 1 matches and 0 failures"
        expect(formatter).to receive(:success_message).with(msg)
        subject.print_summary
      end
    end

    context "with failures" do
      before { subject.failure 'fail' }

      it "prints a failure summary" do
        msg = "SUMMARY: 0 matches and 1 failures"
        expect(formatter).to receive(:failure_message).with(msg)
        subject.print_summary
      end
    end
  end

  describe "#stop?" do
    context "with a failure limit" do

      let(:options) { double(fail_fast: true, stop_after: 3, detail: false) }
      before do
        subject.failure 'first'
        subject.failure 'second'
      end

      it "returns true when the limit is reached " do
        subject.failure 'third'
        expect(subject.stop?).to be true
      end

      it "returns false when under the limit" do
        expect(subject.stop?).to be false
      end
    end

    context "with no failure limit" do
      let(:options) { double(fail_fast: false, detail: false) }

      it "return false" do
        expect(subject.stop?).to be false
      end
    end
  end
end
