require_relative 'garak_spec_helper'

RSpec.describe 'Garak output artifacts' do
  subject(:mod) do
    garak_test_runner(Msf::Plugin::Garak::Runner)
  end

  it 'retains the Garak log, report, hitlog and HTML report' do
    Dir.mktmpdir do |directory|
      garak_directory = File.join(directory, 'garak')
      run_directory = File.join(garak_directory, 'garak_runs')
      FileUtils.mkdir_p(run_directory)
      File.write(File.join(garak_directory, 'garak.log'), 'internal diagnostics')
      File.write(File.join(run_directory, 'garak.test.report.jsonl'), 'report')
      File.write(File.join(run_directory, 'garak.test.hitlog.jsonl'), 'hitlog')
      File.write(File.join(run_directory, 'garak.test.report.html'), 'html')
      stored = []
      allow(mod).to receive(:store_loot) do |type, content_type, _host, _data, filename, *_args|
        stored << [type, content_type, filename]
        "/tmp/#{filename}"
      end
      expect(mod).to receive(:import_report).with('report', association: { host: '192.0.2.1' })

      reports = mod.store_garak_artifacts(directory, association: { host: '192.0.2.1' })

      expect(reports.map { |path| File.basename(path) }).to eq(['garak.test.report.jsonl'])
      expect(stored).to contain_exactly(
        ['garak.log', 'text/plain', 'garak.log'],
        ['garak.hitlog', 'application/x-ndjson', 'garak.test.hitlog.jsonl'],
        ['garak.report.html', 'application/octet-stream', 'garak.test.report.html']
      )
    end
  end
end
