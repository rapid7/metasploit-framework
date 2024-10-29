require 'spec_helper'

load Metasploit::Framework.root.join('msfupdate').to_path

RSpec.describe Msfupdate do

  def dummy_pathname
    Pathname.new(File.dirname(__FILE__)).join('dummy')
  end

  def dummy_git_pathname
    dummy_pathname.join('gitbase')
  end

  def dummy_install_pathname
    dummy_pathname.join('installbase').join('msf3')
  end

  def dummy_apt_pathname
    dummy_pathname.join('aptbase')
  end

  let(:msfbase_dir) do
    dummy_git_pathname
  end

  let(:stdin)  { StringIO.new("", "rb") }
  let(:stdout) { StringIO.new("", "wb") }
  let(:stderr) { StringIO.new("", "wb") }

  subject do
    Msfupdate.new(msfbase_dir, stdin, stdout, stderr)
  end

  before(:context) do
    # Create some fake directories to mock our different install environments
    dummy_pathname.mkpath
    dummy_apt_pathname.join('.apt').mkpath
    dummy_git_pathname.join('.git').mkpath
    dummy_install_pathname.mkpath
    dummy_install_pathname.join('..', 'engine').mkpath
    FileUtils.touch(dummy_install_pathname.join('..', 'engine', 'update.rb'))
  end

  after(:context) do
    dummy_pathname.rmtree
  end

  before(:example) do
    # By default, we want to ensure tests never actually try to execute any
    # of the update methods unless we are explicitly testing them
    allow(subject).to receive(:update_binary_install!)
    allow(subject).to receive(:update_git!)
  end

  context "#parse_args" do
    it "doesn't alter ARGV" do
      ARGV.clear
      ARGV << 'foo'
      subject.parse_args(['x', 'y'])
      expect(ARGV).to eq ['foo']
    end

    context "with --help" do
      let(:args) { ['--help'] }

      it "calls usage" do
        expect(subject).to receive(:usage)
        begin
          subject.parse_args(args)
        rescue SystemExit
        end
      end

      it "exits before updating" do
        expect {subject.parse_args(args)}.to raise_error(SystemExit)
      end
    end

    context "with --git-branch" do
      let(:git_branch) { 'foo' }
      let(:args) { ['--git-branch', git_branch] }

      it "sets @git_branch" do
        subject.parse_args(args)
        expect(subject.instance_variable_get(:@git_branch)).to eq git_branch
      end

      context "without a space" do
        let(:args) { ["--git-branch=#{git_branch}"] }

        it "sets @git_branch" do
          subject.parse_args(args)
          expect(subject.instance_variable_get(:@git_branch)).to eq git_branch
        end
      end
    end

    context "with --git-remote" do
      let(:git_remote) { 'foo' }
      let(:args) { ['--git-remote', git_remote] }

      it "sets @git_remote" do
        subject.parse_args(args)
        expect(subject.instance_variable_get(:@git_remote)).to eq git_remote
      end

      context "without a space" do
        let(:args) { ["--git-remote=#{git_remote}"] }

        it "sets @git_remote" do
          subject.parse_args(args)
          expect(subject.instance_variable_get(:@git_remote)).to eq git_remote
        end
      end
    end

    context "with --offline-file" do
      let(:offline_file) { 'foo' }
      let(:args) { ['--offline-file', offline_file] }

      it "sets @offline_file" do
        subject.parse_args(args)
        expect(subject.instance_variable_get(:@offline_file)).to match Regexp.new(Regexp.escape(offline_file))
      end

      context "with relative path" do
        it "transforms argument into an absolute path" do
          subject.parse_args(args)
          expect(subject.instance_variable_get(:@offline_file)).to eq File.join(Dir.pwd, offline_file)
        end
      end

      context "with absolute path" do
        let(:offline_file) { '/tmp/foo' }
        it "accepts an absolute path" do
          subject.parse_args(args)
          expect(subject.instance_variable_get(:@offline_file)).to eq offline_file
        end
      end

      context "without a space" do
        let(:args) { ["--offline-file=#{offline_file}"] }

        it "sets @offline_file" do
          subject.parse_args(["--offline-file=#{offline_file}"])
          expect(subject.instance_variable_get(:@offline_file)).to match Regexp.new(Regexp.escape(offline_file))
        end
      end
    end

    context "with wait" do
      let(:args) { ['wait'] }
      it "sets @actually_wait" do
        subject.parse_args(args)
        expect(subject.instance_variable_get(:@actually_wait)).to eq true
      end
    end

    context "with nowait" do
      let(:args) { ['nowait'] }
      it "sets @actually_wait" do
        subject.parse_args(args)
        expect(subject.instance_variable_get(:@actually_wait)).to eq false
      end
    end
  end

  context "#run!" do
    before(:example) do
      subject.parse_args(args)
    end
    let(:args) { [] }

    it "calls validate_args" do
      expect(subject).to receive(:validate_args) { true }
      subject.run!
    end

    it "exits if arguments are invalid" do
      allow(subject).to receive(:validate_args).and_return(false)
      expect(subject).to receive(:maybe_wait_and_exit).and_raise(SystemExit)
      expect { subject.run! }.to raise_error(SystemExit)
    end
  end

  context "in an apt installation" do
    let(:msfbase_dir) { dummy_apt_pathname }

    it { expect(subject.apt?).to be_truthy }
    it { expect(subject.binary_install?).to be_falsey }
    it { expect(subject.git?).to be_falsey }

    context "#validate_args" do
      before(:example) do
        subject.parse_args(args)
      end

      context "with no args" do
        let(:args) { [] }
        it { expect(subject.validate_args).to be_truthy }
      end

      context "with --git-remote" do
        let(:args) { ['--git-remote', 'foo'] }
        it { expect(subject.validate_args).to be_falsey }
      end

      context "with --git-branch" do
        let(:args) { ['--git-branch', 'foo'] }
        it { expect(subject.validate_args).to be_falsey }
      end

      context "with --offline-file" do
        let(:args) { ['--offline-file', 'foo'] }
        it { expect(subject.validate_args).to be_falsey }
      end
    end

    context "#run!" do
      it "does not call update_binary_install!" do
        expect(subject).not_to receive(:update_binary_install!)
        subject.run!
      end
      it "does not call update_git!" do
        expect(subject).not_to receive(:update_git!)
        subject.run!
      end
    end
  end

  context "in a binary installation" do
    let(:msfbase_dir) { dummy_install_pathname }

    it { expect(subject.apt?).to be_falsey }
    it { expect(subject.binary_install?).to be_truthy }
    it { expect(subject.git?).to be_falsey }

    context "#validate_args" do
      before(:example) do
        subject.parse_args(args)
      end

      context "with no args" do
        let(:args) { [] }
        it { expect(subject.validate_args).to be_truthy }
      end

      context "with --git-remote" do
        let(:args) { ['--git-remote', 'foo'] }
        it { expect(subject.validate_args).to be_falsey }
      end

      context "with --git-branch" do
        let(:args) { ['--git-branch', 'foo'] }
        it { expect(subject.validate_args).to be_falsey }
      end

      context "with --offline-file" do
        let(:args) { ['--offline-file', 'foo'] }
        it { expect(subject.validate_args).to be_truthy }
      end
    end

    context "#run!" do
      it "calls update_binary_install!" do
        expect(subject).to receive(:update_binary_install!)
        subject.run!
      end
      it "does not call update_git!" do
        expect(subject).not_to receive(:update_git!)
        subject.run!
      end
    end

    context "#update_binary_install!" do
      # TODO: Add more tests!
    end
  end

  context "in a git installation" do
    let(:msfbase_dir) { dummy_git_pathname }

    it { expect(subject.apt?).to be_falsey }
    it { expect(subject.binary_install?).to be_falsey }
    it { expect(subject.git?).to be_truthy }


    context "#validate_args" do
      before(:example) do
        subject.parse_args(args)
      end

      context "with no args" do
        let(:args) { [] }
        it { expect(subject.validate_args).to be_truthy }
      end

      context "with --git-remote" do
        let(:args) { ['--git-remote', 'foo'] }
        it { expect(subject.validate_args).to be_truthy }
      end

      context "with --git-branch" do
        let(:args) { ['--git-branch', 'foo'] }
        it { expect(subject.validate_args).to be_truthy }
      end

      context "with --offline-file" do
        let(:args) { ['--offline-file', 'foo'] }
        it { expect(subject.validate_args).to be_falsey }
      end
    end

    context "#run!" do
      it "does not call update_binary_install!" do
        expect(subject).not_to receive(:update_binary_install!)
        subject.run!
      end
      it "calls update_git!" do
        expect(subject).to receive(:update_git!)
        subject.run!
      end
    end

    context "#update_git!" do
      # TODO: Add more tests!
    end
  end

end
