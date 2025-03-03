##
# This script checks the status of URLs from a provided JSON file.
# It validates if URLs are alive, handles redirects, and fetches Wayback Machine snapshots for URLs that are down.
# It logs the status of each URL, including errors, redirects, and archived snapshots.
#
# Usage: ruby tools/dev/detect_dead_reference_links.rb -f db/modules_metadata_base.json -l WARN
#

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
  MAX_REDIRECTS = 5 # Maximum number of redirects to follow for each URL
  THREAD_POOL_SIZE = 5 # Number of threads in the pool to process URLs concurrently
  CHECKED_URLS_FILE = 'checked_urls.jsonl' # File to save URLs that have been checked
  BATCH_SIZE = 1000 # Number of URLs to process in each batch
  MAX_RETRIES = 3 # Maximum number of retries for failed requests to the Wayback Machine
  RETRY_DELAY = 5 # Delay in seconds between retries

  # Initializes the UrlChecker instance with given URLs and configuration options
  # @param [Array<Hash>] urls_with_paths A list of URLs with associated paths to check
  # @param [Logger::Level] log_level The logging level (defaults to Logger::INFO)
  def initialize(urls_with_paths, log_level: Logger::INFO)
    @urls_with_paths = urls_with_paths
    @results = []
    @checked_urls = load_checked_urls
    @url_times = []
    @logger = Logger.new($stdout)
    @logger.level = log_level
    @total_urls = urls_with_paths.size
    @processed_urls = 0
  end

  # Starts the process of checking all URLs in batches, logging results and saving progress
  # in a thread-safe manner.
  def check_urls
    pool = Concurrent::FixedThreadPool.new(THREAD_POOL_SIZE)
    at_exit { shutdown_thread_pool(pool) }

    # Process URLs in batches to avoid overwhelming the system
    @urls_with_paths.each_slice(BATCH_SIZE) do |batch|
      futures = batch.map do |url_with_path|
        Concurrent::Promises.future(pool) do
          result = check_url(url_with_path)
          @results << result
          @checked_urls << url_with_path[:url]
          save_progress(result)

          update_progress
        end
      end

      # Wait for all futures in the current batch to finish before proceeding
      Concurrent::Promises.zip(*futures).wait!

      # Sleep between batches to avoid overloading the server
      sleep 5
    end

    save_results_to_file
  ensure
    pool.shutdown
    pool.wait_for_termination
    @logger.info('Finished checking URLs.')
  end

  private

  # Filters out URLs that have already been checked.
  # @return [Array<Hash>] List of URLs and paths that have not been checked yet
  def unchecked_urls
    @urls_with_paths.reject { |url_with_path| @checked_urls.include?(url_with_path[:url]) }
  end

  # Checks a single URL and processes its response.
  # @param [Hash] url_with_path The URL and its associated path to check
  # @return [Hash] A result containing the URL, path, status, and archived snapshot (if available)
  def check_url(url_with_path)
    url_result = { url: url_with_path[:url], path: url_with_path[:path], status: nil, archived_snapshot: nil }

    # Skip non-URL references and Wayback links
    if !url_with_path[:url].start_with?('URL-')
      url_result[:status] = 'Skipped (not a URL- reference)'
      return url_result
    elsif url_with_path[:url].start_with?('http://web.archive.org/web')
      url_result[:status] = 'Wayback link (skipped)'
      return url_result
    end

    # Clean the URL and validate it
    cleaned_url = url_with_path[:url].sub(/^URL-/, '')

    # Check if the URL is valid
    if !valid_url?(cleaned_url)
      url_result[:status] = 'Invalid URL'
      return url_result
    end

    # Prepare the HTTP request
    uri = URI.parse(cleaned_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'

    start_time = Time.now

    begin
      # Get the HTTP response and handle redirects
      response = get_response(http, uri)
      follow_redirects(http, uri, response)
    rescue StandardError => e
      handle_error(url_result, e)
    end

    # Process the response (check for success, failure, or error)
    process_response(response, url_result)
    elapsed_time = Time.now - start_time
    @url_times << elapsed_time

    url_result
  ensure
    save_progress(url_result)
  end

  # Validates if a URL is properly formatted
  # @param [String] url The URL to check
  # @return [Boolean] True if the URL is valid, false otherwise
  def valid_url?(url)
    URI.parse(url).is_a?(URI::HTTP)
  rescue StandardError
    false
  end

  # Sends an HTTP GET request to the specified URI
  # @param [Net::HTTP] http The HTTP client
  # @param [URI] uri The URI to send the GET request to
  # @return [Net::HTTPResponse] The HTTP response
  def get_response(http, uri)
    http.get(uri.request_uri)
  end

  # Follows HTTP redirects up to a maximum limit (MAX_REDIRECTS)
  # @param [Net::HTTP] http The HTTP client
  # @param [URI] uri The original URI
  # @param [Net::HTTPResponse] response The HTTP response to process
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

  # Processes the HTTP response to determine the URL status
  # @param [Net::HTTPResponse] response The HTTP response to process
  # @param [Hash] url_result The result hash to update with the status
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

  # Handles errors encountered during URL checking (e.g., network errors)
  # @param [Hash] url_result The result hash to update with error information
  # @param [StandardError] error The error that was raised
  def handle_error(url_result, error)
    url_result[:status] = "Error: #{error.message}"
    url_result[:archived_snapshot] = nil
  end

  # Attempts to fetch the Wayback Machine snapshot for the URL
  # @param [Hash] url_result The result hash to update with the Wayback snapshot information
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

  # Processes the response from the Wayback Machine API
  # @param [Net::HTTPResponse] response The response from the Wayback Machine
  # @param [Hash] url_result The result hash to update with the archived snapshot URL
  def handle_wayback_response(response, url_result)
    if response.is_a?(Net::HTTPSuccess)
      data = JSON.parse(response.body)
      snapshot = data.dig('archived_snapshots', 'closest', 'url')
      url_result[:archived_snapshot] = snapshot || 'No archived version found'
    else
      url_result[:archived_snapshot] = 'Error fetching Wayback Machine data'
    end
  end

  # Saves the final results of the URL checks to a JSON file
  def save_results_to_file
    File.open('url_check_results.json', 'w') { |file| file.write(JSON.pretty_generate(@results)) }
    @logger.info('Results have been saved to "url_check_results.json".')
  end

  # Saves the progress of checked URLs to a file
  # @param [Hash] result The result of a single URL check
  def save_progress(result)
    File.open(CHECKED_URLS_FILE, 'a') { |file| file.puts JSON.generate(result) }
  end

  # Loads the list of already checked URLs from the progress file
  # @return [Array<String>] A list of checked URLs
  def load_checked_urls
    return [] unless File.exist?(CHECKED_URLS_FILE)

    File.readlines(CHECKED_URLS_FILE).map { |row| JSON.parse(row)['url'] }
  end

  # Shuts down the thread pool after URL checking is complete
  # @param [Concurrent::FixedThreadPool] pool The thread pool to shut down
  def shutdown_thread_pool(pool)
    pool.shutdown
    pool.wait_for_termination
    @logger.info('Thread pool shut down successfully.')
  end

  # Updates the progress bar based on the number of URLs processed
  def update_progress
    @processed_urls += 1
    percentage = (@processed_urls.to_f / @total_urls * 100).round
    bar_length = 50
    progress = ('=' * (percentage / 2)).ljust(bar_length, ' ')
    print "\r[#{progress}] #{percentage}% (#{@processed_urls}/#{@total_urls})"
  end
end

# Main entry point to run the URL checking process
if __FILE__ == $PROGRAM_NAME
  options = {}
  OptionParser.new do |opts|
    opts.banner = 'Usage: ruby url_checker.rb [options]'

    opts.on('-f', '--file FILE', 'JSON file containing URLs and paths') do |file|
      options[:file] = file
    end

    opts.on('-l', '--log-level LEVEL', 'Log level (DEBUG, INFO, WARN, ERROR, FATAL, UNKNOWN)') do |log_level|
      options[:log_level] = log_level.upcase.to_sym
    end
  end.parse!

  # Validate input file
  unless options[:file] && File.exist?(options[:file])
    puts 'Please provide a valid JSON file with URLs and paths.'
    exit 1
  end

  # Handling for log level
  log_level = options[:log_level] || 'INFO'
  log_level = Logger.const_get(log_level)

  # Parse the JSON file containing URLs and paths
  urls_with_paths = JSON.parse(File.read(options[:file]))

  # Map the data to the format required by the checker
  mapped_data = urls_with_paths.flat_map do |_path, metadata|
    metadata['references'].map { |ref| { 'path' => metadata['path'], 'ref' => ref } }
  end

  # Validate the structure of the mapped data
  unless mapped_data.is_a?(Array) && mapped_data.all? { |entry| entry['ref'] && entry['path'] }
    puts "Invalid JSON structure. The file should contain an array of objects with 'ref' and 'path' keys."
    exit 1
  end

  # Create the final list of URLs and paths
  urls_with_paths_final = mapped_data.map { |entry| { url: entry['ref'], path: entry['path'] } }

  start_time = Time.now

  # Create and run the UrlChecker instance
  url_checker = UrlChecker.new(urls_with_paths_final, log_level: log_level)
  url_checker.check_urls


  end_time = Time.now
  # Calculate and display the total time taken
  elapsed_time = end_time - start_time
  minutes = (elapsed_time / 60).to_i
  seconds = (elapsed_time % 60).to_i

  puts "\nTotal time taken: #{minutes} minutes and #{seconds} seconds"
end
