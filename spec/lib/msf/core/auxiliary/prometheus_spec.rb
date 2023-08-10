# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Auxiliary::Prometheus do
  subject do
    mod = Msf::Auxiliary.new
    mod.extend(Msf::Auxiliary::Prometheus)
    mod
  end

  describe '#process_node_exporter_data' do
    context 'correctly processes nil' do
      it 'returns a nil' do
        expect(subject.process_results_page(nil)).to eql(nil)
      end
    end

    context 'correctly processes non-data lines' do
      it 'returns an empty hash' do
        expect(subject.process_results_page('# some description')).to eql([])
      end
    end

    context 'correctly processes line with no labels and a double value' do
      it 'returns a hash' do
        expect(subject.process_results_page('go_memstats_alloc_bytes 1.605264e+06')).to eql([{ 'go_memstats_alloc_bytes' => { 'labels' => {}, 'value' => '1.605264e+06' } }])
      end
    end

    context 'correctly processes line with no labels and an integer value' do
      it 'returns a hash' do
        expect(subject.process_results_page('go_memstats_alloc_bytes 1')).to eql([{ 'go_memstats_alloc_bytes' => { 'labels' => {}, 'value' => '1' } }])
      end
    end

    context 'correctly processes line with simple label containing empty value' do
      it 'returns a hash' do
        expect(subject.process_results_page('go_gc_duration_seconds{quantile=""} 2.8197e-05')).to eql([{ 'go_gc_duration_seconds' => { 'value' => '2.8197e-05', 'labels' => { 'quantile' => '' } } }])
      end
    end

    context 'correctly processes line with simple label containing value' do
      it 'returns a hash' do
        expect(subject.process_results_page('go_gc_duration_seconds{quantile="1"} 2.8197e-05')).to eql([{ 'go_gc_duration_seconds' => { 'value' => '2.8197e-05', 'labels' => { 'quantile' => '1' } } }])
      end
    end

    context 'correctly processes line with complex label containing values' do
      it 'returns a hash' do
        expect(subject.process_results_page('node_filesystem_avail_bytes{device="/dev/sda1",fstype="vfat",mountpoint="/boot/efi"} 1.118629888e+09')).to eql([{ 'node_filesystem_avail_bytes' => { 'value' => '1.118629888e+09', 'labels' => { 'device' => '/dev/sda1', 'fstype' => 'vfat', 'mountpoint' => '/boot/efi' } } }])
      end
    end

    context 'correctly processes multiple line with complex label containing values' do
      it 'returns a hash' do
        expect(subject.process_results_page("node_filesystem_avail_bytes{device=\"/dev/sda1\",fstype=\"vfat\",mountpoint=\"/boot/efi\"} 1.118629888e+09\n" \
        'node_filesystem_avail_bytes{device="/dev/sda2",fstype="vfat",mountpoint="/boot/efi2"} 1.118629888e+09')).to eql([
          {
            'node_filesystem_avail_bytes' =>
                       {
                         'labels' =>
                                      { 'device' => '/dev/sda1', 'fstype' => 'vfat', 'mountpoint' => '/boot/efi' },
                         'value' => '1.118629888e+09'
                       }
          },
          {
            'node_filesystem_avail_bytes' =>
              {
                'labels' =>
                                                                                                                                                    { 'device' => '/dev/sda2', 'fstype' => 'vfat', 'mountpoint' => '/boot/efi2' },
                'value' => '1.118629888e+09'
              }
          }
        ])
      end
    end
  end
end
