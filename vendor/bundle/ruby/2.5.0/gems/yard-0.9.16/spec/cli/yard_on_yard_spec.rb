# frozen_string_literal: true

$TOPDIR = File.expand_path(File.join(File.dirname(__FILE__), '../..'))

require 'fileutils'

RSpec.describe YARD::CLI::Yardoc do
  include FileUtils

  context 'building the documentation of YARD itself' do
    before(:context) do
      rm_rf File.join($TOPDIR, 'doc')
      rm_rf File.join($TOPDIR, '.yardoc')

      # Note: as this is very time consuming, we do it only once
      Dir.chdir($TOPDIR) do
        @res = YARD::CLI::Yardoc.new.run('--title', 'YARD-On-YARD')
      end
    end

    it 'succeeds and creates doc/ and .yardoc/' do
      expect(@res).to be true
      expect(Dir.exist?('doc')).to be true
      expect(Dir.exist?('.yardoc')).to be true
    end

    it 'writes the given title in each documentation file' do
      Dir.glob(File.join($TOPDIR, 'doc/**/*.html')) do |htmlfile|
        next if %w(
          frames file_list class_list method_list tag_list _index
        ).include?(File.basename(htmlfile, '.html'))
        html = File.read(htmlfile)

        expect(html.index('&mdash; YARD-On-YARD')).to be >= 0
      end
    end
  end
end if ENV['CI'] || ENV['YY']
