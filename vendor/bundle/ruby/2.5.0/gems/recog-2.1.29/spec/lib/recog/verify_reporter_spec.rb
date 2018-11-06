require 'recog/verify_reporter'

describe Recog::VerifyReporter do
  let(:formatter) { double('formatter').as_null_object }
  let(:fingerprint) { double(name: 'a name', tests: tests) }
  let(:tests) { [double, double, double] }
  let(:summary_line) do
    "SUMMARY: Test completed with 1 successful, 1 warnings, and 1 failures"
  end

  subject { Recog::VerifyReporter.new(double(detail: false, quiet: false, warnings: true), formatter) }

  def run_report
    subject.report(1) do
        subject.print_name fingerprint
        subject.success 'passed'
        subject.warning 'a warning'
        subject.failure 'a failure'
    end
  end

  describe "#report" do
    it "prints warnings" do
      expect(formatter).to receive(:warning_message).with('a warning')
      run_report
    end

    it "prints failures" do
      expect(formatter).to receive(:failure_message).with('a failure')
      run_report
    end

    it "prints summary" do
      expect(formatter).to receive(:failure_message).with(summary_line)
      run_report
    end

    context "with detail" do
      subject { Recog::VerifyReporter.new(double(detail: true, quiet: false, warnings: true), formatter) }

      it "prints the fingerprint name" do
        expect(formatter).to receive(:status_message).with("\na name")
        run_report
      end

      it "prints successes" do
        expect(formatter).to receive(:success_message).with('   passed')
        run_report
      end

      it "prints warnings" do
        expect(formatter).to receive(:warning_message).with('   a warning')
        run_report
      end

      it "prints failures" do
        expect(formatter).to receive(:failure_message).with('   a failure')
        run_report
      end

      it "prints the fingerprint count" do
        expect(formatter).to receive(:status_message).with("\nVerified 1 fingerprints:")
        run_report
      end

      it "prints summary" do
        expect(formatter).to receive(:failure_message).with(summary_line)
        run_report
      end

      context "with no fingerprint tests" do
        let(:tests) { [] }

        it "does not print the name" do
          expect(formatter).not_to receive(:status_message).with("\na name")
          run_report
        end
      end
    end
  end

  describe "#print_summary" do
    context "with success" do
      before { subject.success 'pass' }

      it "prints a successful summary" do
        msg = "SUMMARY: Test completed with 1 successful, 0 warnings, and 0 failures"
        expect(formatter).to receive(:success_message).with(msg)
        subject.print_summary
      end
    end

    context "with warnings" do
      before { subject.warning 'warn' }

      it "prints a warning summary" do
        msg = "SUMMARY: Test completed with 0 successful, 1 warnings, and 0 failures"
        expect(formatter).to receive(:warning_message).with(msg)
        subject.print_summary
      end
    end

    context "with failures" do
      before { subject.failure 'fail' }

      it "prints a failure summary" do
        msg = "SUMMARY: Test completed with 0 successful, 0 warnings, and 1 failures"
        expect(formatter).to receive(:failure_message).with(msg)
        subject.print_summary
      end
    end
  end
end
