#!/usr/bin/env ruby

##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script will check multiple files against VirusTotal's public analysis service. You are
# limited to at most 4 requests (of any nature in any given 1 minute time frame), because
# VirusTotal says so. If you prefer your own API key, you may get one at virustotal.com
#
# VirusTotal Terms of Service:
# https://www.virustotal.com/en/about/terms-of-service/
#
# Public API documentations can be found here:
# https://www.virustotal.com/en/documentation/public-api/
# https://api.vtapi.net/en/doc/
#
# WARNING:
# When you upload or otherwise submit content, you give VirusTotal (and those we work with) a
# worldwide, royalty free, irrevocable and transferable licence to use, edit, host, store,
# reproduce, modify, create derivative works, communicate, publish, publicly perform, publicly
# display and distribute such content.
#
# Author:
# sinn3r <sinn3r[at]metasploit.com>
#


msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'
require 'rex'
require 'msf/core'
require 'digest/sha2'
require 'optparse'
require 'json'
require 'timeout'

#
# Prints a status message
#
def print_status(msg='')
  $stdout.puts "[*] #{msg}"
end


#
# Prints an error message
#
def print_error(msg='')
  $stdout.puts "[-] #{msg}"
end


module VirusTotalUtility

class ToolConfig

  def initialize
    @config_file ||= Msf::Config.config_file
    @group_name  ||= 'VirusTotal'
  end

  #
  # Saves the VirusTotal API key to Metasploit's config file
  # @param key [String] API key
  # @return [void]
  #
  def save_api_key(key)
    _set_setting('api_key', key)
  end


  #
  # Returns the VirusTotal API key from Metasploit's config file
  # @return [String] the API key
  #
  def load_api_key
    _get_setting('api_key') || ''
  end


  #
  # Sets the privacy waiver to true after the tool is run for the very first time
  # @return [void]
  #
  def save_privacy_waiver
    _set_setting('waiver', true)
  end


  #
  # Returns whether a waver is set or not
  # @return [Boolean]
  #
  def has_privacy_waiver?
    _get_setting('waiver') || false
  end


  private


  #
  # Sets a setting in Metasploit's config file
  # @param key_name [String] The Key to set
  # @param value [String] The value to set
  # @return [void]
  #
  def _set_setting(key_name, value)
    ini = Rex::Parser::Ini.new(@config_file)
    ini.add_group(@group_name) if ini[@group_name].nil?
    ini[@group_name][key_name] = value
    ini.to_file(@config_file)
  end


  #
  # Returns a setting from Metasploit's config file
  # @param key_name [String] The setting to get
  # @return [void]
  #
  def _get_setting(key_name)
    ini = Rex::Parser::Ini.new(@config_file)
    group = ini[@group_name]
    return nil if group.nil?
    return nil if group[key_name].nil?

    group[key_name]
  end

end


class VirusTotal < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(opts={})
    @api_key     = opts['api_key']
    @sample_info = _load_sample(opts['sample'])

    # It should resolve to 74.125.34.46, and the HOST header (HTTP) must be www.virustotal.com, or
    # it will return a 404 instead.
    rhost = Rex::Socket.resolv_to_dotted("www.virustotal.com") rescue '74.125.34.46'

    # Need to configure HttpClient to enable SSL communication
    super(
      'DefaultOptions' =>
        {
          'SSL'   => true,
          'RHOST' => rhost,
          'RPORT' => 443
        }
    )
  end


  #
  # Submits a malware sample for VirusTotal to scan
  # @param sample [String] Data to analyze
  # @return [Hash] JSON response
  #
  def scan_sample
    opts = {
      'boundary' => 'THEREAREMANYLIKEITBUTTHISISMYDATA',
      'api_key'  => @api_key,
      'filename' => @sample_info['filename'],
      'data'     => @sample_info['data']
    }

    _execute_request({
      'uri'    => '/vtapi/v2/file/scan',
      'method' => 'POST',
      'vhost'  => 'www.virustotal.com',
      'ctype'  => "multipart/form-data; boundary=#{opts['boundary']}",
      'data'   => _create_upload_data(opts)
    })
  end


  #
  # Returns the report of a specific malware checksum
  # @return [Hash] JSON response
  #
  def retrieve_report
    _execute_request({
      'uri'       => '/vtapi/v2/file/report',
      'method'    => 'POST',
      'vhost'     => 'www.virustotal.com',
      'vars_post' => {
        'apikey'   => @api_key,
        'resource' => @sample_info['sha256']
      }
    })
  end

  private

  #
  # Returns the JSON response of a HTTP request
  # @param opts [Hash] HTTP options
  # @return [Hash] JSON response
  #
  def _execute_request(opts)
    res = send_request_cgi(opts)

    return '' if res.nil?
    case res.code
    when 204
      raise RuntimeError, "You have hit the request limit."
    when 403
      raise RuntimeError, "No privilege to execute this request probably due to an invalye API key"
    end

    json_body = ''

    begin
      json_body = JSON.parse(res.body)
    rescue JSON::ParserError
      json_body = ''
    end

    json_body
  end

  #
  # Returns malware sample information
  # @param sample [String] The sample path to load
  # @return [Hash] Information about the sample (including the raw data, and SHA256 checksum)
  #
  def _load_sample(sample)
    info = {
      'filename' => '',
      'data'     => ''
    }

    File.open(sample, 'rb') do |f|
      info['data'] = f.read
    end

    info['filename'] = File.basename(sample)
    info['sha256']   = Digest::SHA256.hexdigest(info['data'])

    info
  end


  #
  # Creates a form-data message
  # @param opts [Hash] A hash that contains keys including boundary, api_key, filename, and data
  # @return [String] The POST request data
  #
  def _create_upload_data(opts={})
    boundary = opts['boundary']
    api_key  = opts['api_key']
    filename = opts['filename']
    data     = opts['data']

    # Can't use Rex::MIME::Message, or you WILL be increditably outraged, it messes with your data.
    # See VT report for example: 4212686e701286ab734d8a67b7b7527f279c2dadc27bd744abebecab91b70c82
    data = %Q|--#{boundary}
Content-Disposition: form-data; name="apikey"

#{api_key}
--#{boundary}
Content-Disposition: form-data; name="file"; filename="#{filename}"
Content-Type: application/octet-stream

#{data}
--#{boundary}--
|

    data
  end

end

class OptsConsole
  #
  # Return a hash describing the options.
  #
  def self.parse(args)
    options = {}

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{__FILE__} [options]"

      opts.separator ""
      opts.separator "Specific options:"

      opts.on("-k", "-k <key>", "(Optional) Virusl API key to use") do |v|
        options['api_key'] = v
      end

      opts.on("-d", "-delay <seconds>", "(Optional) Number of seconds to wait for the report") do |v|
        if v !~ /^\d+$/
          print_error("Invalid input for -d. It must be a number.")
          exit
        end

        options['delay'] = v.to_i
      end

      opts.on("-q", "-quick", "(Optional) Do a checksum search without uploading the sample") do |v|
        options['quick'] = true
      end

      opts.on("-f", "-files <filenames>", "Files to scan") do |v|
        files = v.split.delete_if { |e| e.nil? }
        bad_files = []
        files.each do |f|
          unless ::File.exists?(f)
            bad_files << f
          end
        end

        unless bad_files.empty?
          print_error("Cannot find: #{bad_files * ' '}")
          exit
        end

        if files.length > 4
          print_error("Sorry, I can only allow 4 files at a time.")
          exit
        end

        options['samples'] = files
      end

      opts.separator ""
      opts.separator "Common options:"

      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end
    end

    # Set default
    if options['samples'].nil?
      options['samples'] = []
    end

    if options['quick'].nil?
      options['quick'] = false
    end

    if options['delay'].nil?
      options['delay'] = 60
    end

    if options['api_key'].nil?
      # Default key is from Metasploit, see why this key can be shared:
      # http://blog.virustotal.com/2012/12/public-api-request-rate-limits-and-tool.html
      options['api_key'] = '501caf66349cc7357eb4398ac3298fdd03dec01a3e2f3ad576525aa7b57a1987'
    end

    begin
      opts.parse!(args)
    rescue OptionParser::InvalidOption
      print_error("Invalid option, try -h for usage")
      exit
    end

    if options.empty?
      print_error("No options specified, try -h for usage")
      exit
    end

    options
  end
end

class Driver

  attr_reader :opts

  def initialize
    opts = {}

    # Init arguments
    options = OptsConsole.parse(ARGV)

    # Init config manager
    config = ToolConfig.new

    # User must ack for research privacy before using this tool
    unless config.has_privacy_waiver?
      ack_privacy
      config.save_privacy_waiver
    end

    # Set the API key
    config.save_api_key(options['api_key']) unless options['api_key'].blank?
    api_key = config.load_api_key
    if api_key.blank?
      print_status("No API key found, using the default one. You may set it later with -k.")
      exit
    else
      print_status("Using API key: #{api_key}")
      opts['api_key'] = api_key
    end

    @opts = opts.merge(options)
  end


  #
  # Prompts the user about research privacy. They will not be able to get out until they enter 'Y'
  # @return [Boolean] True if ack
  #
  def ack_privacy
    print_status "WARNING: When you upload or otherwise submit content, you give VirusTotal"
    print_status "(and those we work with) a worldwide, royalty free, irrevocable and transferable"
    print_status "licence to use, edit, host, store, reproduce, modify, create derivative works,"
    print_status "communicate, publish, publicly perform, publicly display and distribute such"
    print_status "content. To read the complete Terms of Service for VirusTotal, please go to the"
    print_status "following link:"
    print_status "https://www.virustotal.com/en/about/terms-of-service/"
    print_status 
    print_status "If you prefer your own API key, you may obtain one at VirusTotal."

    while true
     $stdout.print "[*] Enter 'Y' to acknowledge: "
     if $stdin.gets =~ /^y|yes$/i
        return true
      end
    end
  end


  #
  # Retrieves a report from VirusTotal
  # @param vt [VirusTotal] VirusTotal object
  # @param res [Hash] Last submission response
  # @param delay [Fixnum] Delay
  # @return [Hash] VirusTotal response that contains the report
  #
  def wait_report(vt, res, delay)
    sha256 = res['sha256']
    print_status("Requesting the report...")
    res = nil

    # 3600 seconds = 1 hour
    begin
      ::Timeout.timeout(3600) {
      while true
        res = vt.retrieve_report
        break if res['response_code'] == 1
        select(nil, nil, nil, delay)
        print_status("Received code #{res['response_code']}. Waiting for another #{delay.to_s} seconds...")
      end
      }
    rescue ::Timeout::Error
      print_error("No report collected. Please manually check the analysis link later.")
      return nil
    end

    res
  end


  #
  # Shows the scan report
  # @param res [Hash] VirusTotal response
  # @param sample [String] Malware name
  # @return [void]
  #
  def generate_report(res, sample)
    if res['response_code'] != 1
      print_status("VirusTotal: #{res['verbose_msg']}")
      return
    end

    short_filename = File.basename(sample)
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => "Analysis Report: #{short_filename} (#{res['positives']} / #{res['total']}): #{res['sha256']}",
      'Indent'  => 1,
      'Columns' => ['Antivirus', 'Detected', 'Version', 'Result', 'Update']
    )

    (res['scans'] || []).each do |result|
      product  = result[0]
      detected = result[1]['detected'].to_s
      version  = result[1]['version'] || ''
      sig_name = result[1]['result']  || ''
      timestamp = result[1]['update'] || ''

      tbl << [product, detected, version, sig_name, timestamp]
    end

    print_status tbl.to_s
  end


  #
  # Displays checksums
  #
  def show_checksums(res)
    print_status("Sample MD5 checksum    : #{res['md5']}")     if res['md5']
    print_status("Sample SHA1 checksum   : #{res['sha1']}")    if res['sha1']
    print_status("Sample SHA256 checksum : #{res['sha256']}")  if res['sha256']
    print_status("Analysis link: #{res['permalink']}")         if res['permalink']
  end


  #
  # Executes a scan by uploading a sample and produces a report
  #
  def scan_by_upload
    @opts['samples'].each do |sample|
      vt = VirusTotal.new({'api_key' => @opts['api_key'], 'sample' => sample})
      print_status("Please wait while I upload #{sample}...")
      res = vt.scan_sample
      print_status("VirusTotal: #{res['verbose_msg']}")
      show_checksums(res)
      res = wait_report(vt, res, @opts['delay'])
      generate_report(res, sample) if res

      puts
    end
  end


  #
  # Executes a checksum search and produces a report
  #
  def scan_by_checksum
    @opts['samples'].each do |sample|
      vt = VirusTotal.new({'api_key' => @opts['api_key'], 'sample' => sample})
      print_status("Please wait I look for a report for #{sample}...")
      res = vt.retrieve_report
      show_checksums(res)
      generate_report(res, sample) if res

      puts
    end
  end

end

end # VirusTotalUtility


#
# main
#
if __FILE__ == $PROGRAM_NAME
  begin
    driver = VirusTotalUtility::Driver.new
    if driver.opts['quick']
      driver.scan_by_checksum
    else
      driver.scan_by_upload
    end
  rescue Interrupt
    $stdout.puts
    $stdout.puts "Good bye"
  end
end
