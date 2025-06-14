#!/usr/bin/env ruby

require 'diff-lcs'
require 'json'
require 'base64'
require 'open3'
require 'optparse'

YSOSERIAL_RANDOMIZED_HEADER = 'ysoserial/Pwner'.freeze
PAYLOAD_TEST_MIN_LENGTH = 0x0101
PAYLOAD_TEST_MAX_LENGTH = 0x0102
YSOSERIAL_MODIFIED_TYPES = %w[bash cmd powershell].freeze
YSOSERIAL_UNMODIFIED_TYPE = 'none'.freeze
YSOSERIAL_ALL_TYPES = ([YSOSERIAL_UNMODIFIED_TYPE] + YSOSERIAL_MODIFIED_TYPES).freeze

@debug = false
@generate_all = false
@payload_type = YSOSERIAL_UNMODIFIED_TYPE
@ysoserial_payloads = []
@json_document = {}
OptionParser.new do |opts|
  opts.banner = "Usage #{File.basename($PROGRAM_NAME)} [options]"

  opts.on('-a', '--all', 'Generate all types of payloads') do
    @generate_all = true
  end

  opts.on('-d', '--debug', 'Debug mode (output offset information only)') do
    @debug = true
  end

  opts.on('-h', '--help', 'Help') do
    puts opts
    abort
  end

  opts.on('-m', '--modified [TYPE]', String, 'Use \'ysoserial-modified\' with the specified payload type') do |modified_type|
    @payload_type = modified_type
  end

  opts.on('-p', '--payload [PAYLOAD]', String, 'Specified ysoserial payload') do |payload|
    @ysoserial_payloads << payload
  end

  opts.on('-j', '--json [PATH]', String, 'Update an existing JSON document') do |json_path|
    @json_document = JSON.parse(File.read(json_path))
  end
end.parse!

def generate_payload(payload_name, search_string_length)
  # Generate a string of specified length and embed it into an ASCII-encoded ysoserial payload
  search_string = 'A' * search_string_length

  # Build the command line with ysoserial parameters
  if @payload_type == YSOSERIAL_UNMODIFIED_TYPE
    stdout, stderr, _status = Open3.capture3('java', '-jar', 'ysoserial-original.jar', payload_name, search_string)
  else
    stdout, stderr, _status = Open3.capture3('java', '-jar', 'ysoserial-modified.jar', payload_name, @payload_type, search_string)
  end

  payload = stdout
  payload.force_encoding('binary')

  if @debug && payload.empty? && !stderr.empty?
    # Pipe errors out to the console
    warn(stderr.split("\n").each { |i| i.prepend('    ') })
  elsif stderr.include? 'java.lang.IllegalArgumentException'
    # STDERR.puts "  WARNING: '#{payload_name}' requires complex args and may not be supported"
    return nil
  elsif stderr.include? 'Error while generating or serializing payload'
    # STDERR.puts "  WARNING: '#{payload_name}' errored and may not be supported"
    return nil
  elsif stdout == "\xac\xed\x00\x05\x70"
    # STDERR.puts "  WARNING: '#{payload_name}' returned null and may not be supported"
    return nil
  else
    # STDERR.puts "  Successfully generated #{payload_name} using #{YSOSERIAL_BINARY}"

    # Strip out the semi-randomized ysoserial string and trailing newline
    payload.gsub!(/#{YSOSERIAL_RANDOMIZED_HEADER}[[:digit:]]{13,14}/, 'ysoserial/Pwner00000000000000')
    return payload
  end
end

def generate_payload_array(payload_name)
  # Generate and return a number of payloads, each with increasingly longer strings, for future comparison
  payload_array = []
  (PAYLOAD_TEST_MIN_LENGTH..PAYLOAD_TEST_MAX_LENGTH).each do |i|
    payload = generate_payload(payload_name, i)
    return nil if payload.nil?

    payload_array[i] = payload
  end

  payload_array
end

def length_offset?(current_byte, next_byte)
  # If this byte has been changed, and is different by one, then it must be a length value
  if next_byte && current_byte.position == next_byte.position && current_byte.action == '-' && (next_byte.element.ord - current_byte.element.ord == 1)
    return true
  end

  false
end

def buffer_offset?(current_byte, next_byte)
  # If this byte has been inserted, then it must be part of the increasingly large payload buffer
  if (current_byte.action == '+' && (next_byte.nil? || (current_byte.position != next_byte.position)))
    return true
  end

  false
end

def diff(blob_a, blob_b)
  return nil if blob_a.nil? || blob_b.nil?

  diffs = Diff::LCS.diff(blob_a, blob_b)
  diffs.flatten(1)
end

def get_payload_list
  # Call ysoserial and return the list of payloads that can be generated
  payloads = `java -jar ysoserial-original.jar 2>&1`
  payloads.encode!('ASCII', 'binary', invalid: :replace, undef: :replace, replace: '')
  payloads = payloads.split("\n")

  # Make sure the headers are intact, then skip over them
  abort unless payloads[0] == 'Y SO SERIAL?'
  payloads = payloads.drop_while { |line| !line.strip.start_with?('Payload') }
  payloads = payloads.drop(2)

  payload_list = []
  payloads.each do |line|
    # Skip the header rows
    next unless line.start_with? '     '

    payload_list.push(line.match(/^ +([^ ]+)/)[1])
  end

  payload_list - ['JRMPClient', 'JRMPListener']
end

# YSOSERIAL_MODIFIED_TYPES.unshift(YSOSERIAL_ORIGINAL_TYPE)
def generated_ysoserial_payloads
  results = {}
  @payload_list.each do |payload|
    warn "Generating payloads for #{payload}..."

    empty_payload = generate_payload(payload, 0)

    if empty_payload.nil?
      warn "  ERROR: Errored while generating '#{payload}' and it will not be supported"
      results[payload] = { status: 'unsupported' }
      next
    end

    payload_array = generate_payload_array(payload)

    length_offsets = []
    buffer_offsets = []

    # Comparing diffs of various payload lengths to find length and buffer offsets
    (PAYLOAD_TEST_MIN_LENGTH..PAYLOAD_TEST_MAX_LENGTH).each do |i|
      # Compare this binary with the next one
      diffs = diff(payload_array[i], payload_array[i + 1])

      break if diffs.nil?

      # Iterate through each diff, searching for offsets of the length and the payload
      diffs.length.times do |j|
        current_byte = diffs[j]
        next_byte = diffs[j + 1]
        prev_byte = diffs[j - 1]

        if j > 0 && (prev_byte.position == current_byte.position)
          # Skip this if we compared these two bytes on the previous iteration
          next
        end

        # Compare this byte and the following byte to identify length and buffer offsets
        length_offsets.push(current_byte.position) if length_offset?(current_byte, next_byte)
        buffer_offsets.push(current_byte.position) if buffer_offset?(current_byte, next_byte)
      end
    end

    if @debug
      for length_offset in length_offsets
        warn "  LENGTH OFFSET #{length_offset} = 0x#{empty_payload[length_offset - 1].ord.to_s(16)} #{empty_payload[length_offset].ord.to_s(16)}"
      end

      for buffer_offset in buffer_offsets
        warn "  BUFFER OFFSET #{buffer_offset}"
      end
      warn "  PAYLOAD LENGTH: #{empty_payload.length}"
    end

    payload_bytes = Base64.strict_encode64(empty_payload)
    if buffer_offsets.empty?
      # TODO: Turns out ysoserial doesn't have any static payloads.  Consider removing this.
      results[payload] = {
        status: 'static',
        bytes: payload_bytes
      }
    else
      results[payload] = {
        status: 'dynamic',
        lengthOffset: length_offsets.uniq,
        bufferOffset: buffer_offsets.uniq,
        bytes: payload_bytes
      }
    end
  end
  results
end

@payload_list = get_payload_list
unless @ysoserial_payloads.empty?
  unknown_list = @ysoserial_payloads - @payload_list
  if unknown_list.empty?
    @payload_list = @ysoserial_payloads
  else
    warn "ERROR: Invalid payloads specified: #{unknown_list.join(', ')}"
    abort
  end
end

if @generate_all
  YSOSERIAL_ALL_TYPES.each do |type|
    warn "Generating payload type for #{type}..."
    @payload_type = type
    @json_document[type] ||= {}
    @json_document[type].merge!(generated_ysoserial_payloads)
    $stderr.puts
  end
else
  @json_document[@payload_type] ||= {}
  @json_document[@payload_type].merge!(generated_ysoserial_payloads)
end

payload_count = {}
payload_count['skipped'] = 0
payload_count['static'] = 0
payload_count['dynamic'] = 0

@json_document.each_value do |vs|
  vs.each_value do |v|
    case v[:status]
    when 'unsupported'
      payload_count['skipped'] += 1
    when 'static'
      payload_count['static'] += 1
    when 'dynamic'
      payload_count['dynamic'] += 1
    end
  end
end

unless @debug
  puts JSON.pretty_generate(@json_document)
end

warn "DONE!  Successfully generated #{payload_count['static']} static payloads and #{payload_count['dynamic']} dynamic payloads.  Skipped #{payload_count['skipped']} unsupported payloads."
