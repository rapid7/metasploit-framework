#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/http'
require 'nokogiri'
require 'thread'

module ReleaseNotesFinder
  # This finds the release notes information based on either:
  # 1. A PR number. In release notes, PR numbers are for bug fixes and notable changes.
  # 2. A module short name. For example: ms08_067_netapi
  class Client
    attr_accessor :release_notes

    RELEASE_NOTES_PAGE = 'https://community.rapid7.com/docs/DOC-2918'.freeze

    def initialize
      init_release_notes
      @mutex = Mutex.new
    end

    def add_release_notes_entry(row)
      td = row.search('td')
      release_notes_link = td[0] && td[0].at('a') ? td[0].at('a').attributes['href'].value : ''
      release_notes_num = td[0] && td[0].at('a') ? td[0].at('a').text.scan(/\d{10}/).flatten.first || '' : ''
      highlights = td[1] ? (td[1].search('span') || []).map { |e| e.text } * " " : ''
      update_link = td[2] && td[2].at('a') ? td[2].at('a').attributes['href'].value : ''

      @release_notes << {
        release_notes_link: release_notes_link,
        release_notes_num: release_notes_num,
        highlights: highlights,
        update_link: update_link,
        pull_requests: [],
        new_modules: []
      }
    end

    def init_release_notes
      self.release_notes = []

      html = send_http_request(RELEASE_NOTES_PAGE)
      table_rows_pattern = 'div[@id="jive-body-main"]//div//section//div//div[@class="j-rte-table"]//table//tbody//tr'
      rows = html.search(table_rows_pattern)
      rows.each do |row|
        add_release_notes_entry(row)
      end
    end

    def update_pr_list(n, text)
      pr_num, desc = text.scan(/#(\d+).\x20*(.+)/).flatten
      return unless pr_num
      n[:pull_requests] << { id: pr_num, description: desc }
    end

    def update_module_list(n, li)
      li.search('a').each do |a|
        next if a.attributes['href'].nil?
        n[:new_modules] << { link: a.attributes['href'].value }
      end
    end

    def update_release_notes_entry(n)
      html = send_http_request(n[:release_notes_link])
      pattern = '//div[@class="jive-rendered-content"]//ul//li'
      html.search(pattern).each do |li|
        @mutex.synchronize do
          update_pr_list(n, li.text)
          update_module_list(n, li)
        end
      end
    end

    def get_release_notes(input)
      release_notes.each do |n|
        if n[:pull_requests].empty?
          update_release_notes_entry(n)
        end

        input_type = guess_input_type(input)

        case input_type
        when :pr
          m = get_release_notes_from_pr(n, input)
        when :module_name
          m = get_release_notes_from_module_name(n, input)
        end

        return m if m
      end

      nil
    end

    def guess_input_type(input)
      input =~ /^\d+/ ? :pr : :module_name
    end

    def get_release_notes_from_module_name(n, input)
      n[:new_modules].each do |m|
        return n if m[:link] && m[:link].include?(input)
      end

      nil
    end

    def get_release_notes_from_pr(n, pr)
      n[:pull_requests].each do |p|
        return n if p[:id] && pr == p[:id]
      end

      nil
    end

    def send_http_request(uri)
      url = URI.parse(uri)
      cli = Net::HTTP.new(url.host, url.port)
      cli.use_ssl = true
      req = Net::HTTP::Get.new(url.request_uri)
      res = cli.request(req)
      Nokogiri::HTML(res.body)
    end
  end
end

def main
  inputs = []

  ARGV.length.times { inputs << ARGV.shift }
  puts "[*] Enumerating release notes..."
  cli = ReleaseNotesFinder::Client.new
  puts "[*] Finding release notes for items: #{inputs * ', '}"
  threads = []
  begin
    inputs.each do |input|
      t = Thread.new do
        n = cli.get_release_notes(input)
        puts "\n"

        if n
          puts "[*] Found release notes for: #{input}"
          puts "Release Notes Number: #{n[:release_notes_num]}"
          puts "Release Notes Link: #{n[:release_notes_link] || 'N/A'}"
          puts "Update Link: #{n[:update_link] || 'N/A'}"
          puts "Highlights:\n#{n[:highlights]}"
        else
          puts "[*] Unable to find release notes for: #{input}"
        end
      end
      threads << t
    end
    threads.each { |t| t.join }
  ensure
    threads.each { |t| t.kill }
  end
end

if __FILE__ == $PROGRAM_NAME
  main
end
