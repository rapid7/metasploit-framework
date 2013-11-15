require 'spec_helper'

load Metasploit::Framework.root.join('msfupdate').to_path

describe Msfupdate do

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

  let(:stdout) { StringIO.new("", "wb") }
  let(:stderr) { StringIO.new("", "wb") }

  subject do
    Msfupdate.new(msfbase_dir, stdout, stderr)
  end

  before(:all) do
    # Create some fake directories to mock our different install environments
    dummy_pathname.mkpath
    dummy_apt_pathname.join('.apt').mkpath
    dummy_git_pathname.join('.git').mkpath
    dummy_install_pathname.mkpath
    dummy_install_pathname.join('..', 'engine').mkpath
    FileUtils.touch(dummy_install_pathname.join('..', 'engine', 'update.rb'))
  end

  after(:all) do
    dummy_pathname.rmtree
  end

  before(:each) do
    # By default, we want to ensure tests never actually try to execute any
    # of the update methods unless we are explicitly testing them
    subject.stub(:update_apt!)
    subject.stub(:update_binary_install!)
    subject.stub(:update_git!)
  end

  context "#parse_args" do
    it "doesn't alter ARGV" do
      ARGV.clear
      ARGV << 'foo'
      subject.parse_args(['x', 'y'])
      ARGV.should == ['foo']
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
        subject.instance_variable_get(:@git_branch).should == git_branch
      end

      context "without a space" do
        let(:args) { ["--git-branch=#{git_branch}"] }

        it "sets @git_branch" do
          subject.parse_args(args)
          subject.instance_variable_get(:@git_branch).should == git_branch
        end
      end
    end

    context "with --git-remote" do
      let(:git_remote) { 'foo' }
      let(:args) { ['--git-remote', git_remote] }

      it "sets @git_remote" do
        subject.parse_args(args)
        subject.instance_variable_get(:@git_remote).should == git_remote
      end

      context "without a space" do
        let(:args) { ["--git-remote=#{git_remote}"] }

        it "sets @git_remote" do
          subject.parse_args(args)
          subject.instance_variable_get(:@git_remote).should == git_remote
        end
      end
    end

    context "with --offline-file" do
      let(:offline_file) { 'foo' }
      let(:args) { ['--offline-file', offline_file] }

      it "sets @offline_file" do
        subject.parse_args(args)
        subject.instance_variable_get(:@offline_file).should =~ Regexp.new(Regexp.escape(offline_file))
      end

      context "with relative path" do
        it "transforms argument into an absolute path" do
          subject.parse_args(args)
          subject.instance_variable_get(:@offline_file).should == File.join(Dir.pwd, offline_file)
        end
      end

      context "with absolute path" do
        let(:offline_file) { '/tmp/foo' }
        it "accepts an absolute path" do
          subject.parse_args(args)
          subject.instance_variable_get(:@offline_file).should == offline_file
        end
      end

      context "without a space" do
        let(:args) { ["--offline-file=#{offline_file}"] }

        it "sets @offline_file" do
          subject.parse_args(["--offline-file=#{offline_file}"])
          subject.instance_variable_get(:@offline_file).should =~ Regexp.new(Regexp.escape(offline_file))
        end
      end
    end

    context "with wait" do
      let(:args) { ['wait'] }
      it "sets @actually_wait" do
        subject.parse_args(args)
        subject.instance_variable_get(:@actually_wait).should == true
      end
    end

    context "with nowait" do
      let(:args) { ['nowait'] }
      it "sets @actually_wait" do
        subject.parse_args(args)
        subject.instance_variable_get(:@actually_wait).should == false
      end
    end
  end

  context "in an apt installation" do
    let(:msfbase_dir) { dummy_apt_pathname }

    its(:apt?) { should == true }
    its(:binary_install?) { should == false }
    its(:git?) { should == false }

    context "#run!" do
      it "calls update_apt!" do
        subject.should_receive(:update_apt!)
        subject.run!
      end
      it "does not call update_binary_install!" do
        subject.should_not_receive(:update_binary_install!)
        subject.run!
      end
      it "does not call update_git!" do
        subject.should_not_receive(:update_git!)
        subject.run!
      end
    end

    context "#update_apt!" do
      # TODO: Add more tests!
    end
  end

  context "in a binary installation" do
    let(:msfbase_dir) { dummy_install_pathname }

    its(:apt?) { should == false }
    its(:binary_install?) { should == true }
    its(:git?) { should == false }

    context "#run!" do
      it "does not call update_apt!" do
        subject.should_not_receive(:update_apt!)
        subject.run!
      end
      it "calls update_binary_install!" do
        subject.should_receive(:update_binary_install!)
        subject.run!
      end
      it "does not call update_git!" do
        subject.should_not_receive(:update_git!)
        subject.run!
      end
    end

    context "#update_binary_install!" do
      # TODO: Add more tests!
    end
  end

  context "in a git installation" do
    let(:msfbase_dir) { dummy_git_pathname }

    its(:apt?) { should == false }
    its(:binary_install?) { should == false }
    its(:git?) { should == true }

    context "#run!" do
      it "does not call update_apt!" do
        subject.should_not_receive(:update_apt!)
        subject.run!
      end
      it "does not call update_binary_install!" do
        subject.should_not_receive(:update_binary_install!)
        subject.run!
      end
      it "calls update_git!" do
        subject.should_receive(:update_git!)
        subject.run!
      end
    end

    context "#update_git!" do
      # TODO: Add more tests!
    end
  end

end
