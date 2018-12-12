require 'rex'
require 'msf/core/module/reference'
require 'msf/util/document_generator'
require 'msf/util/document_generator/pull_request_finder'

RSpec.describe Msf::Util::DocumentGenerator::DocumentNormalizer do

  let(:mod_description)   { 'MS08-067 netapi double' }
  let(:mod_authors)       { [ 'sinn3r' ] }
  let(:mod_fullname)      { 'exploit/windows/smb/ms08_067_netapi' }
  let(:mod_shortname)     { 'ms08_067_netapi' }
  let(:mod_name)          { 'MS08-067' }
  let(:mod_pull_requests) { good_pull_requests }
  let(:mod_refs)          { [Msf::Module::SiteReference.new('URL', 'http://example.com')] }
  let(:mod_platforms)     { 'win' }
  let(:mod_options)       { { 'RHOST' => rhost_option } }
  let(:mod_normal_rank)   { 300 }
  let(:mod_type)          { 'exploit' }

  let(:good_pull_requests) do
    {
      '1234' => { title: 'Merged Pull Request' }
    }
  end

  let(:mod_targets) do
    target = double('target')
    allow(target).to receive(:name).and_return('Automatic')
    [target]
  end

  let(:bad_pull_requests) do
    exp = Msf::Util::DocumentGenerator::PullRequestFinder::Exception.new
    allow(exp).to receive(:message).and_return('GITHUB_OAUTH_TOKEN')
    exp
  end

  let(:rhost_option) do
    owner = double('Msf::Exploit::Remote::SMB::Client')
    option = double('Msf::OptAddress')
    allow(option).to receive(:name).and_return('RHOST')
    allow(option).to receive(:advanced).and_return(false)
    allow(option).to receive(:evasion).and_return(false)
    allow(option).to receive(:required).and_return(true)
    allow(option).to receive(:desc).and_return('The target address')
    allow(option).to receive(:default).and_return(nil)
    allow(option).to receive(:owner).and_return(owner)
    option
  end

  let(:msf_mod) do
    mod = double('Msf::Module')
    mod_info = { 'Author' => mod_authors, 'Platform' => mod_platforms }
    allow(mod).to receive(:description).and_return(mod_description)
    allow(mod).to receive(:module_info).and_return(mod_info)
    allow(mod).to receive(:fullname).and_return(mod_fullname)
    allow(mod).to receive(:name).and_return(mod_name)
    allow(mod).to receive(:references).and_return(mod_refs)
    allow(mod).to receive(:platforms).and_return(mod_platforms)
    allow(mod).to receive(:authors).and_return(mod_authors)
    allow(mod).to receive(:rank).and_return(mod_normal_rank)
    allow(mod).to receive(:options).and_return(mod_options)
    allow(mod).to receive(:type).and_return(mod_type)
    allow(mod).to receive(:shortname).and_return(mod_shortname)
    allow(mod).to receive(:targets).and_return(mod_targets)
    allow(mod).to receive(:side_effects).and_return([])
    allow(mod).to receive(:stability).and_return([])
    allow(mod).to receive(:reliability).and_return([])
    mod
  end


  subject do
    described_class.new
  end

  describe '#get_md_content' do
    context 'when metadata is given' do
      it 'returns the documentation in HTML' do
        items = {
          mod_description:   msf_mod.description,
          mod_authors:       msf_mod.send(:module_info)['Author'],
          mod_fullname:      msf_mod.fullname,
          mod_name:          msf_mod.name,
          mod_pull_requests: good_pull_requests,
          mod_refs:          msf_mod.references,
          mod_rank:          msf_mod.rank,
          mod_platforms:     msf_mod.send(:module_info)['Platform'],
          mod_options:       msf_mod.options,
          mod_side_effects:  msf_mod.side_effects,
          mod_reliability:   msf_mod.reliability,
          mod_stability:     msf_mod.stability,
          mod_demo:          msf_mod
        }
        expect(subject.get_md_content(items, '')).to include('<html>')
      end
    end
  end

  describe '#load_css' do
    it 'loads CSS from file' do
      expect(subject.send(:load_css)).to include('color: #0069d6')
    end
  end

  describe '#md_to_html' do
    let(:md) do
      %Q|# Hello world!|
    end

    context 'when a markdown file is given' do
      it 'returns the documentation in HTML' do
        expect(subject.send(:md_to_html, md, '')).to include('<h1>Hello world!</h1>')
      end
    end
  end

  describe 'normalize_pull_requests' do
    context 'when a hash of pull requests are given' do
      it 'returns HTML links' do
        expect(subject.send(:normalize_pull_requests, good_pull_requests)).to include('](https://github.com/')
      end
    end

    context 'when PullRequestFinder::Exception is raised' do
      it 'includes a how-to link in the error message' do
        how_to_link = 'https://help.github.com/articles/creating-an-access-token-for-command-line-use/'
        expect(subject.send(:normalize_pull_requests, bad_pull_requests)).to include(how_to_link)
      end
    end
  end

  describe 'normalize_options' do
    context 'when datastore options are given' do
      it 'returns a list of options in HTML' do
        expect(subject.send(:normalize_options, msf_mod.options)).to include('* RHOST - The target address')
      end
    end
  end

  describe 'normalize_description' do
    context 'when a description is a long one-liner' do
      it 'returns the wrapped the description' do
        desc = 'description ' * 20
        expect(subject.send(:normalize_description, desc)).to include("\ndescription")
      end
    end
  end

  describe 'normalize_authors' do
    context 'when an array of authors is given' do
      it 'returns the author list in markdown' do
        expect(subject.send(:normalize_authors, msf_mod.authors)).to include('* ')
      end
    end
  end

  describe 'normalize_targets' do
    context 'when an array of targets is given' do
      it 'returns the target list in HTML' do
        expect(subject.send(:normalize_targets, msf_mod.targets)).to include('* Automatic')
      end
    end
  end

  describe 'normalize_references' do
    context 'when an array of references is given' do
      it 'returns the reference list in HTML' do
        expect(subject.send(:normalize_references, msf_mod.references)).to include('* [http://')
      end
    end
  end

  describe 'normalize_platforms' do
    context 'when platforms win and linux are given' do
      it 'returns the markdown with windows and linux' do
        platforms = ['win', 'linux']

        platforms.each do |platform|
          expect(subject.send(:normalize_platforms, platforms)).to include("* #{platform}")
        end
      end
    end

    context 'when a platform as a string is given' do
      it 'returns the platform' do
        expect(subject.send(:normalize_platforms, msf_mod.platforms)).to eq(mod_platforms)
      end
    end
  end

  describe 'normalize_rank' do
    context 'when a rank is given' do
      it 'returns the rank' do
        expect(subject.send(:normalize_rank, msf_mod.rank)).to include('Normal')
      end

      it 'includes a wiki about exploit ranks' do
        wiki = 'https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking'
        expect(subject.send(:normalize_rank, msf_mod.rank)).to include(wiki)
      end
    end
  end

  describe 'load_demo_template' do
    context 'when a BrowserExploitServer demo template path is given' do
      it 'returns the demo' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::BES_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include('This module is also supported by Browser Autopwn 2')
      end
    end
  end

  describe 'normalize_demo_output' do
    context 'when the module is a kind of Msf::Exploit::Remote::HttpServer' do
      it 'returns the demo of HTTPSERVER_DEMO_TEMPLATE' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::HTTPSERVER_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include("use #{mod_fullname}")
      end
    end

    context 'when the module is a remote exploit' do
      it 'returns the demo of REMOTE_EXPLOIT_DEMO_TEMPLATE' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::REMOTE_EXPLOIT_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include('it looks like this is a remote exploit module')
      end
    end

    context 'when the module is a kind of Msf::Exploit::Local' do
      it 'returns the content of LOCALEXPLOIT_DEMO_TEMPLATE' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::LOCALEXPLOIT_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include('To run a local exploit, make sure you are at the msf prompt.')
      end
    end

    context 'when the module is a kind of Msf::Post' do
      it 'returns the demo of POST_DEMO_TEMPLATE' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::POST_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include('There are two ways to execute this post module')
      end
    end

    context 'when the module is a kind of Msf::Payload' do
      it 'returns the demo of PAYLOAD_DEMO_TEMPLATE' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::PAYLOAD_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include('> generate')
      end
    end

    context 'when the module is a kind of Msf::Auxiliary::Scanner' do
      it 'returns the demo of AUXILIARY_SCANNER_DEMO_TEMPLATE' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::AUXILIARY_SCANNER_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include('This module is a scanner module')
      end
    end

    context 'when the module does not have a known kind' do
      it 'returns the demo of GENERIC_DEMO_TEMPLATE' do
        template = Msf::Util::DocumentGenerator::DocumentNormalizer::GENERIC_DEMO_TEMPLATE
        expect(subject.send(:load_demo_template, msf_mod, template)).to include('msf exploit')
      end
    end
  end

end
