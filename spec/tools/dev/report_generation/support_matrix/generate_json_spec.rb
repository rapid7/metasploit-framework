require 'spec_helper'
require 'json'
require 'open3'
require 'rbconfig'
require 'tmpdir'

RSpec.describe 'support matrix JSON output' do
  let(:script_path) { File.expand_path('../../../../../tools/dev/report_generation/support_matrix/generate.rb', __dir__) }

  def generate_json(*arguments)
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, script_path, '--format', 'json', *arguments)
    raise "Report generation failed: #{stderr}" unless status.success?

    JSON.parse(stdout)
  end

  it 'renders compatibility data from a JSON file' do
    data = { 'sessions' => [{ 'session_type' => 'fixture/session', 'metadata' => { 'example' => 'value' }, 'commands' => [] }] }
    Dir.mktmpdir('support matrix ') do |directory|
      path = File.join(directory, 'input.json')
      File.write(path, JSON.generate(data))
      expect(generate_json('--data-path', path)).to eq(data)
    end
  end

  it 'renders an empty session list' do
    Dir.mktmpdir('support-matrix') do |directory|
      path = File.join(directory, 'input.json')
      File.write(path, JSON.generate('sessions' => []))
      expect(generate_json('--data-path', path)).to eq('sessions' => [])
    end
  end

  it 'renders data extracted from Allure attachments' do
    session = { 'session_type' => 'fixture/session', 'commands' => [] }
    parameters = [{ 'name' => 'host_runner_image', 'value' => 'fixture-runner' }]
    result = { 'attachments' => [{ 'name' => 'available commands', 'source' => 'commands.json' }], 'parameters' => parameters }
    Dir.mktmpdir('support-matrix') do |directory|
      File.write(File.join(directory, 'fixture-result.json'), JSON.generate(result))
      File.write(File.join(directory, 'commands.json'), JSON.generate('sessions' => [session]))
      expected = { 'sessions' => [session.merge('metadata' => { 'host_runner_image' => 'fixture-runner' })] }
      expect(generate_json('--allure-data', directory)).to eq(expected)
    end
  end
end
