require 'rex'
require 'msf/util/document_generator'
require 'octokit'
require 'net/http'

RSpec.describe Msf::Util::DocumentGenerator::PullRequestFinder do

  let(:author_name) { 'name' }

  let(:commit) do
    c = double('commit')
    allow(c).to receive(:author).and_return({author: author_name, login: author_name})
    allow(c).to receive(:sha).and_return('sha')
    c
  end

  let(:commits) do
      [ commit ]
  end

  let(:pr_num) { '5486' }

  let(:html) do
    %Q|
    <html>
    <head></head>
    <body>
    <li class="pull-request">(<a href="/rapid7/metasploit-framework/pull/#{pr_num}" title="Merged Pull Request: adobe_flash_copy_pixels_to_byte_array: Execution from the flash renderer / Windows 8.1">##{pr_num}</a>)</li>
    </body>
    </html>
    |
  end

  subject do
    obj = described_class.new
    obj.git_access_token = 'GITHUB_AUTH_TOKEN'

    octo = Octokit::Client.new
    allow(octo).to receive(:commits).and_return(commits)
    allow(obj).to receive(:git_client).and_return(octo)
    obj
  end

  let(:http_response) do
    req = double('HttpResponse')
    allow(req).to receive(:body).and_return(html)
    req
  end

  let(:module_name) { 'modules/windows/browser/adobe_flash_copy_pixels_to_byte_array.rb' }

  let(:msf_mod) do
    mod = double('Msf::Module')
    init = double('Msf::Module#initialize')
    allow(init).to receive(:source_location).and_return([ module_name ])
    allow(mod).to receive(:method).with(any_args).and_return(init)
    mod
  end

  before(:each) do
    allow(ENV).to receive(:has_key?).and_return(true)
    allow_any_instance_of(Net::HTTP).to receive(:request).with(any_args).and_return(http_response)
  end

  describe '#initialize' do
    it 'sets the owner property' do
      expect(subject.owner).to eq('rapid7')
    end

    it 'sets the repository' do
      expect(subject.repository).to eq('rapid7/metasploit-framework')
    end

    it 'sets the branch' do
      expect(subject.branch).to eq('master')
    end

    it 'sets the git access token' do
      subject1 = described_class.new
      subject1.git_access_token = 'FAKE KEY'
      subject2 = described_class.new
      expect(subject2.git_access_token).not_to eq(subject1.git_access_token)
    end

    it 'sets Octokit::Client' do
      expect(subject.git_client).to be_kind_of(Octokit::Client)
    end
  end

  describe '#search' do
    context 'when a module is given' do
      it 'returns a hash of pull requests' do
        result = subject.search(msf_mod)
        expect(result).to be_kind_of(Hash)
        expect(result.keys.first).to eq(pr_num)
        expect(result.first[1][:number]).to eq(pr_num)
        expect(result.first[1][:title]).to include('Merged Pull Request')
      end
    end
  end

  describe '#get_normalized_module_name' do
    context 'when a module is given' do
      it 'returns the module name' do
        expect(subject.send(:get_normalized_module_name, msf_mod)).to eq(module_name)
      end
    end
  end

  describe '#get_commits_from_file' do
    context 'when a module path is given' do
      it 'returns commits' do
        expect(subject.send(:get_commits_from_file, module_name)).to eq(commits)
      end
    end
  end

  describe '#get_author' do
    context 'when a commit is given' do
      it 'returns the author name' do
        expect(subject.send(:get_author, commit)).to eq(author_name)
      end
    end
  end

  describe '#is_author_blacklisted?' do
    context 'when a commit authored by tabassassin is given' do
      it 'returns true' do
        c = double('commit')
        allow(c).to receive(:author).and_return({author: 'tabassassin', login: 'tabassassin'})
        expect(subject.send(:is_author_blacklisted?, c)).to be_truthy
      end
    end

    context 'when a commit authored by a human is given' do
      it 'returns false' do
        expect(subject.send(:is_author_blacklisted?, commit)).to be_falsey
      end
    end
  end

  describe '#get_pull_requests_from_commits' do
    context 'when commits are given' do
      it 'returns pull requests' do
        pr = subject.send(:get_pull_requests_from_commits, commits)
        expect(pr).to be_kind_of(Hash)
        expect(pr.keys.first).to eq(pr_num)
      end
    end
  end

  describe '#get_pull_request_from_commit' do
    context 'when a commit is given' do
      it 'returns a pull request' do
        pr = subject.send(:get_pull_request_from_commit, commit)
        expect(pr).to be_kind_of(Hash)
        expect(pr[:number]).to eq(pr_num)
      end
    end
  end

end
