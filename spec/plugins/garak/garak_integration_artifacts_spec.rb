require_relative 'garak_spec_helper'

RSpec.describe 'Garak output artifacts' do
  subject(:mod) do
    garak_test_runner(Msf::Plugin::Garak::Runner)
  end

  it 'retains the Garak log, report, hitlog and HTML report' do
    Dir.mktmpdir do |directory|
      garak_directory = File.join(directory, 'garak')
      report_prefix = File.join(directory, 'scan')
      FileUtils.mkdir_p(garak_directory)
      File.write(File.join(garak_directory, 'garak.log'), 'internal diagnostics')
      File.write("#{report_prefix}.report.jsonl", 'report')
      File.write("#{report_prefix}.hitlog.jsonl", 'hitlog')
      File.write("#{report_prefix}.report.html", 'html')
      stored = []
      allow(mod).to receive(:store_loot) do |type, content_type, _host, _data, filename, *_args|
        stored << [type, content_type, filename]
        "/tmp/#{filename}"
      end
      expect(mod).to receive(:import_report).with('report', association: { host: '192.0.2.1' })

      reports = mod.store_garak_artifacts(directory, report_prefix: report_prefix, association: { host: '192.0.2.1' })

      expect(reports.map { |path| File.basename(path) }).to eq(['scan.report.jsonl'])
      expect(stored).to contain_exactly(
        ['garak.log', 'text/plain', 'garak.log'],
        ['garak.hitlog', 'application/x-ndjson', 'scan.hitlog.jsonl'],
        ['garak.report.html', 'application/octet-stream', 'scan.report.html']
      )
    end
  end
end
