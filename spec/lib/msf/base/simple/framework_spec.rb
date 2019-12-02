require 'spec_helper'

RSpec.describe Msf::Simple::Framework do
  include_context 'Msf::Simple::Framework'

  subject do
    framework
  end

  it_should_behave_like 'Msf::Simple::Framework::ModulePaths'

  describe "#ready" do
    let(:run_uuid) { Rex::Text.rand_text_alphanumeric 24 }
    it "should start out empty" do
      expect(subject.ready).to_not include, run_uuid
    end
    it "should remember things that are ready to run" do
      subject.ready << run_uuid
      expect(subject.ready).to include, run_uuid
    end
    it "should forget things that are running" do
      subject.ready << run_uuid
      subject.ready.delete run_uuid
      expect(subject.ready).to_not include, run_uuid
    end
  end

  describe "#running" do
    let(:run_uuid) { Rex::Text.rand_text_alphanumeric 24 }
    it "should start out empty" do
      expect(subject.running).to_not include, run_uuid
    end
    it "should remember things that are running" do
      subject.running << run_uuid
      expect(subject.running).to include, run_uuid
    end
    it "should forget things that are done" do
      subject.running << run_uuid
      subject.running.delete run_uuid
      expect(subject.running).to_not include, run_uuid
    end
  end

  describe "#results" do
    let(:run_uuid) { Rex::Text.rand_text_alphanumeric 24 }
    it "should start out empty" do
      expect(subject.results.keys).to_not include, run_uuid
    end
    it "should remember results" do
      subject.results[run_uuid] = {}
      expect(subject.results.keys).to include, run_uuid
    end
    it "should forget things that have been acknowleged" do
      subject.results[run_uuid] = {}
      subject.results.delete run_uuid
      expect(subject.results.keys).to_not include, run_uuid
    end
  end
end
