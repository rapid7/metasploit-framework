##
#
# Usage: ruby tools/dev/detect_dead_reference_links.rb -f db/modules_metadata_base.json -l WARN
#
##

require 'net/http'
require 'uri'
require 'json'
require 'csv'
require 'concurrent'
require 'logger'
require 'fileutils'
require 'optparse'
require 'benchmark'

class UrlChecker
  WAYBACK_MACHINE_API_URL = 'https://archive.org/wayback/available?url='
  MAX_REDIRECTS = 5
  THREAD_POOL_SIZE = 5
  CHECKED_URLS_FILE = 'checked_urls.jsonl'
  BATCH_SIZE = 1000
  MAX_RETRIES = 3
  RETRY_DELAY = 5

  def initialize(urls_with_paths, log_level: Logger::INFO)
    @urls_with_paths = urls_with_paths
    @results = []
    @checked_urls = load_checked_urls
    @url_times = []
    @logger = Logger.new(STDOUT)
    @logger.level = log_level
    @total_urls = urls_with_paths.size
    @processed_urls = 0
  end

  def check_urls
    pool = Concurrent::FixedThreadPool.new(THREAD_POOL_SIZE)
    at_exit { shutdown_thread_pool(pool) }

    # Process URLs in batches to prevent excessive memory usage
    @urls_with_paths.each_slice(BATCH_SIZE) do |batch|
      futures = batch.map do |url_with_path|
        Concurrent::Promises.future(pool) do
          result = check_url(url_with_path)
          @results << result
          @checked_urls << url_with_path[:url]
          save_progress(result)

          # Update the progress bar after each URL is processed
          update_progress
        end
      end

      # Wait for batch to finish
      Concurrent::Promises.zip(*futures).wait!
      # Sleep between batches to reduce resource consumption
      sleep 5
    end

    save_results_to_file
  ensure
    pool.shutdown
    pool.wait_for_termination
    @logger.info('Finished checking URLs.')
  end

  private

  def unchecked_urls
    @urls_with_paths.reject { |url_with_path| @checked_urls.include?(url_with_path[:url]) }
  end

  def check_url(url_with_path)
    url_result = { url: url_with_path[:url], path: url_with_path[:path], status: nil, archived_snapshot: nil }

    # Remove "URL-" prefix
    cleaned_url = url_with_path[:url].sub(/^URL-/, '')
    if !valid_url?(cleaned_url)
      url_result[:status] = "Invalid URL"
      return url_result
    end

    uri = URI.parse(cleaned_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'

    start_time = Time.now

    begin
      response = get_response(http, uri)
      follow_redirects(http, uri, response)
    rescue StandardError => e
      handle_error(url_result, e)
    end

    process_response(response, url_result)
    elapsed_time = Time.now - start_time
    @url_times << elapsed_time

    url_result
  ensure
    save_progress(url_result)
  end

  def valid_url?(url)
    URI.parse(url).is_a?(URI::HTTP) rescue false
  end

  def get_response(http, uri)
    http.get(uri.request_uri)
  end

  def follow_redirects(http, uri, response)
    redirect_count = 0
    while response.is_a?(Net::HTTPRedirection) && redirect_count < MAX_REDIRECTS
      location = response['location']
      @logger.info("Redirecting to: #{location}")
      uri = URI.parse(location)
      response = http.get(uri.request_uri)
      redirect_count += 1
    end
  end

  def process_response(response, url_result)
    if response.nil?
      url_result[:status] = 'Error: No response received'
    elsif response.is_a?(Net::HTTPSuccess) || response.is_a?(Net::HTTPRedirection)
      url_result[:status] = 'Alive'
    else
      url_result[:status] = "Not Alive (Status Code: #{response.code})"
      fetch_wayback_snapshot(url_result)
    end
  end

  def handle_error(url_result, error)
    url_result[:status] = "Error: #{error.message}"
    url_result[:archived_snapshot] = nil
  end

  def fetch_wayback_snapshot(url_result)
    wayback_url = "#{WAYBACK_MACHINE_API_URL}#{url_result[:url]}"
    retries = 0

    begin
      uri = URI.parse(wayback_url)
      response = Net::HTTP.get_response(uri)
      handle_wayback_response(response, url_result)
    rescue StandardError => e
      retries += 1
      if retries <= MAX_RETRIES
        @logger.warn("Error fetching Wayback snapshot for #{url_result[:url]}: #{e.message}. Retrying in #{RETRY_DELAY} seconds... (Attempt #{retries} of #{MAX_RETRIES})")
        sleep(RETRY_DELAY)
        retry
      else
        url_result[:archived_snapshot] = "Error fetching Wayback snapshot after #{MAX_RETRIES} attempts: #{e.message}"
      end
    end
  end

  def handle_wayback_response(response, url_result)
    if response.is_a?(Net::HTTPSuccess)
      data = JSON.parse(response.body)
      snapshot = data.dig('archived_snapshots', 'closest', 'url')
      url_result[:archived_snapshot] = snapshot || 'No archived version found'
    else
      url_result[:archived_snapshot] = 'Error fetching Wayback Machine data'
    end
  end

  def save_results_to_file
    File.open('url_check_results.json', 'w') { |file| file.write(JSON.pretty_generate(@results)) }
    @logger.info('Results have been saved to "url_check_results.json".')
  end

  def save_progress(result)
    File.open(CHECKED_URLS_FILE, 'a') { |file| file.puts JSON.generate(result) }
  end

  def load_checked_urls
    return [] unless File.exist?(CHECKED_URLS_FILE)

    File.readlines(CHECKED_URLS_FILE).map { |row| JSON.parse(row)['url'] }
  end

  def shutdown_thread_pool(pool)
    pool.shutdown
    pool.wait_for_termination
    @logger.info('Thread pool shut down successfully.')
  end

  def update_progress
    @processed_urls += 1
    percentage = (@processed_urls.to_f / @total_urls * 100).round
    bar_length = 50
    progress = ('=' * (percentage / 2)).ljust(bar_length, ' ')
    print "\r[#{progress}] #{percentage}% (#{@processed_urls}/#{@total_urls})"
  end
end

if __FILE__ == $0
  options = {}
  OptionParser.new do |opts|
    opts.banner = "Usage: ruby url_checker.rb [options]"

    opts.on("-f", "--file FILE", "JSON file containing URLs and paths") do |file|
      options[:file] = file
    end

    opts.on("-l", "--log-level LEVEL", "Log level (DEBUG, INFO, WARN, ERROR, FATAL, UNKNOWN)") do |log_level|
      options[:log_level] = log_level.upcase.to_sym
    end
  end.parse!

  unless options[:file] && File.exist?(options[:file])
    puts "Please provide a valid JSON file with URLs and paths."
    exit 1
  end

  log_level = options[:log_level] || 'INFO'
  log_level = Logger.const_get(log_level)

  urls_with_paths = JSON.parse(File.read(options[:file]))

  mapped_data = urls_with_paths.flat_map do |_path, metadata|
    metadata['references'].map { |ref| { 'path' => metadata['path'], 'ref' => ref } }
  end

  unless mapped_data.is_a?(Array) && mapped_data.all? { |entry| entry['ref'] && entry['path'] }
    puts "Invalid JSON structure. The file should contain an array of objects with 'ref' and 'path' keys."
    exit 1
  end

  urls_with_paths_final = mapped_data.map { |entry| { url: entry['ref'], path: entry['path'] } }

  url_checker = UrlChecker.new(urls_with_paths_final, log_level: log_level)
  url_checker.check_urls
end
