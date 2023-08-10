# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with Prometheus node exporter
  #
  ###
  module Auxiliary::Prometheus
    def process_results_page(page)
      # data is in a strange 'label{optional_kv_hash-ish} value' format.
      return nil if page.nil?

      results = []
      page.scan(/^(?<name>\w+)(?:{(?<labels>[^}]+)})? (?<value>[\w.+-]+)/).each do |hit|
        result = {}
        value = { 'value' => hit[2], 'labels' => {} }
        if hit[1]
          hit[1].scan(/(?<key>[^=]+?)="(?<value>[^"]*)",?/).each do |label|
            value['labels'][label[0]] = label[1]
          end
        end
        result[hit[0]] = value
        results.append(result)
      end
      return results
    end
  end
end
