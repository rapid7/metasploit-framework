require 'spec_helper'
require 'fileutils'
require 'open3'
require 'rbconfig'
require 'tmpdir'

RSpec.describe 'verify_encoding.rb' do
  let(:checker_path) { File.expand_path('../../../tools/dev/verify_encoding.rb', __dir__) }
  let(:binary_header) { "# -*- coding: binary -*-\n# ascii\n" }

  def run_checker(files)
    Dir.mktmpdir('verify-encoding') do |root|
      script = File.join(root, 'tools', 'dev', 'verify_encoding.rb')
      FileUtils.mkdir_p(File.dirname(script))
      FileUtils.cp(checker_path, script)
      files.each do |name, content|
        path = File.join(root, name)
        FileUtils.mkdir_p(File.dirname(path))
        File.binwrite(path, content)
      end
      Open3.capture3(RbConfig.ruby, script)
    end
  end

  it 'accepts ASCII-only binary-encoded source' do
    _stdout, _stderr, status = run_checker('fixture.rb' => binary_header + "puts 'ascii'\n")
    expect(status).to be_success
  end

  it 'rejects valid UTF-8 non-ASCII characters' do
    _stdout, _stderr, status = run_checker('fixture.rb' => binary_header + "# caf\u00e9\n")
    expect(status).not_to be_success
  end

  it 'keeps the existing non-ASCII character diagnostic' do
    stdout, = run_checker('fixture.rb' => binary_header + "# caf\u00e9\n")
    expect(stdout).to include('line 3, char 6')
  end

  it 'rejects invalid UTF-8 bytes' do
    _stdout, _stderr, status = run_checker('fixture.rb' => binary_header + "# \xff\n".b)
    expect(status).not_to be_success
  end

  it 'identifies the file and line with invalid UTF-8' do
    stdout, = run_checker('fixture.rb' => binary_header + "# \xff\n".b)
    expect(stdout).to match(/invalid UTF-8.*fixture\.rb: line 3/)
  end

  it 'can inspect an encoding declaration followed by invalid UTF-8 on line two' do
    stdout, = run_checker('fixture.rb' => "# -*- coding: binary -*-\n# \xff\n".b)
    expect(stdout).to match(/invalid UTF-8.*fixture\.rb: line 2/)
  end

  it 'continues checking lines after invalid UTF-8' do
    stdout, = run_checker('fixture.rb' => binary_header.b + "# \xff\n".b + "# caf\u00e9\n".b)
    expect(stdout).to include('line 4, char 6')
  end

  it 'continues excluding vendor files' do
    _stdout, _stderr, status = run_checker(
      'fixture.rb' => binary_header + "# ascii\n",
      'vendor/invalid.rb' => binary_header + "# \xff\n".b
    )
    expect(status).to be_success
  end
end
