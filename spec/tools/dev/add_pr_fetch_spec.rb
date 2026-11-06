require 'spec_helper'
require 'fileutils'
require 'open3'
require 'rbconfig'
require 'tmpdir'

RSpec.describe 'add_pr_fetch.rb' do
  let(:git_environment) { ENV.keys.grep(/\AGIT_/).to_h { |key| [key, nil] } }
  let(:repository) { File.join(@directory, 'repository') }
  let(:working_directory) { repository }
  let(:script_path) { File.expand_path('../../../tools/dev/add_pr_fetch.rb', __dir__) }
  let(:pull_refspec) { '+refs/pull/*/head:refs/remotes/origin/pr/*' }

  def git(*arguments, directory: repository)
    stdout, stderr, status = Open3.capture3(git_environment, 'git', *arguments, chdir: directory)
    raise "Git fixture setup failed: #{stderr}" unless status.success?

    stdout
  end

  def run_script
    Open3.capture3(git_environment, RbConfig.ruby, script_path, chdir: working_directory)
  end

  around do |example|
    Dir.mktmpdir('pr-fetch ') do |directory|
      @directory = directory
      example.run
    end
  end

  before do
    FileUtils.mkdir_p(repository)
    git('init', '--quiet', '--initial-branch=main')
    git('remote', 'add', 'origin', 'https://example.test/repository.git')
  end

  it 'runs successfully in an ordinary checkout' do
    expect(run_script.last).to be_success
  end

  it 'adds the pull request refspec to the repository remote' do
    run_script
    expect(git('config', '--get-all', 'remote.origin.fetch').lines.map(&:strip)).to include(pull_refspec)
  end

  it 'does not change the configuration a second time' do
    run_script
    original_config = File.binread(File.join(repository, '.git', 'config'))
    run_script
    expect(File.binread(File.join(repository, '.git', 'config'))).to eq(original_config)
  end

  it 'ignores inherited Git repository variables' do
    original_git_dir = ENV['GIT_DIR']
    ENV['GIT_DIR'] = File.join(@directory, 'unrelated.git')
    expect(run_script.last).to be_success
  ensure
    ENV['GIT_DIR'] = original_git_dir
  end

  context 'in a linked worktree' do
    let(:working_directory) { File.join(@directory, 'linked worktree') }

    before do
      git('-c', 'commit.gpgsign=false', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test',
          'commit', '--quiet', '--allow-empty', '-m', 'Fixture')
      git('worktree', 'add', '--quiet', '-b', 'fixture-worktree', working_directory)
    end

    it 'runs without treating the .git file as a directory' do
      expect(run_script.last).to be_success
    end

    it 'updates the shared repository configuration' do
      run_script
      expect(git('config', '--get-all', 'remote.origin.fetch').lines.map(&:strip)).to include(pull_refspec)
    end

    it 'updates worktree-specific remote fetch configuration' do
      git('config', 'extensions.worktreeConfig', 'true')
      git('config', '--worktree', 'remote.local.fetch', '+refs/heads/*:refs/remotes/local/*', directory: working_directory)

      run_script

      config = git('rev-parse', '--git-path', 'config.worktree', directory: working_directory).strip
      expect(File.binread(config)).to include('fetch = +refs/pull/*/head:refs/remotes/local/pr/*')
    end
  end
end
