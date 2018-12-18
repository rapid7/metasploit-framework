#!/usr/bin/env ruby
# encoding: binary

#TODO: Remove previous line?

require 'diff-lcs'
require 'json'
require 'base64'
require 'open3'

YSOSERIAL_RANDOMIZED_HEADER = "ysoserial/Pwner"
PAYLOAD_TEST_MIN_LENGTH = 4
PAYLOAD_TEST_MAX_LENGTH = 5

def generatePayload(payloadName,searchStringLength)
  program = "ysoserial-original.jar"
  #STDERR.puts " Generating #{payloadName} with length #{searchStringLength} using #{program}"

  # Generate a string of specified length and embed it into an ASCII-encoded ysoserial payload
  searchString = 'A'*searchStringLength
  #STDERR.puts "  Calling java -jar #{program} #{payloadName} '#{searchString}'"
  stdout, stderr, status = Open3.capture3('java', '-jar', program.to_s, payloadName.to_s, searchString.to_s)

  payload = stdout
  payload.force_encoding("binary")

  if payload.length==0 and stderr.length>0
    # Pipe errors out to the console
    STDERR.puts stderr.split("\n").each {|i| i.prepend("    ")}
  elsif stderr.include?"java.lang.IllegalArgumentException"
    #STDERR.puts "  WARNING: '#{payloadName}' with #{program} requires complex args and may not be supported"
    return nil
  elsif stderr.include?"Error while generating or serializing payload"
    #STDERR.puts "  WARNING: '#{payloadName}' with #{program} errored and may not be supported"
    return nil
  elsif stdout == "\xac\xed\x00\x05\x70"
    #STDERR.puts "  WARNING: '#{payloadName}' with #{program} returned null and may not be supported"
    return nil
  else
    #STDERR.puts "  Successfully generated #{payloadName} using #{program}"

    # Strip out the semi-randomized ysoserial string and trailing newline
    payload.gsub!(/#{YSOSERIAL_RANDOMIZED_HEADER}[[:digit:]]+/, 'ysoserial/Pwner00000000000000')
    return payload
  end
end

def generatePayloadArray(payloadName)
  # Generate and return a number of payloads, each with increasingly longer strings, for future comparison
  payloadArray = []
  (PAYLOAD_TEST_MIN_LENGTH..PAYLOAD_TEST_MAX_LENGTH).each do |i|
    payload = generatePayload(payloadName,i)
    return nil if payload.nil?
    payloadArray[i] = payload
  end
  return payloadArray
end

def isLengthOffset?(currByte,nextByte)
  # If this byte has been changed, and is different by one, then it must be a length value
  if nextByte and currByte.position == nextByte.position and currByte.action == "-"
    if nextByte.element.ord - currByte.element.ord == 1
      #STDERR.puts "Found a length offset at #{currByte.position}"
      return true
    end
  end
  return false
end

def isBufferOffset?(currByte,nextByte)
  # If this byte has been inserted, then it must be part of the increasingly large payload buffer
  if (currByte.action == "+" and (nextByte.nil? or (currByte.position != nextByte.position)))
    #STDERR.puts "Found a buffer offset at #{currByte.position}"
    return true
  end
  return false
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
  return diffs
end

def getPayloadList
  # Call ysoserial and return the list of payloads that can be generated
  payloads = `java -jar ysoserial-original.jar 2>&1`
  payloads.encode!('ASCII', 'binary', invalid: :replace, undef: :replace, replace: '')
  payloads = payloads.split("\n")

  # Make sure the headers are intact, then skip over them
  abort unless payloads[0] == "Y SO SERIAL?"
  payloads = payloads.drop(5)

  payloadList = []
  # Skip the header rows
  payloads.each do |line|
    next unless line.start_with?"     "
    payloadList.push(line.scan(/^     ([^ ]*) .*/).first.last)
  end
  return payloadList
end

results = {}
payloadList = getPayloadList
payloadList.each do |payload|
  STDERR.puts "Generating payloads for #{payload}..."

  emptyPayload = generatePayload(payload,0)

  if emptyPayload.nil?
    STDERR.puts "  ERROR: Errored while generating '#{payload}' and it will not be supported"
    results[payload]={"status": "unsupported"}
    next
  end    

  payloadArray = generatePayloadArray(payload)

  lengthOffset = []
  bufferOffset = []

  # Comparing diffs of various payload lengths to find length and buffer offsets
  (PAYLOAD_TEST_MIN_LENGTH..PAYLOAD_TEST_MAX_LENGTH).each do |i|
    # Compare this binary with the next one
    diffs = diff(payloadArray[i],payloadArray[i+1])

    break if diffs.nil?
 
    # Iterate through each diff, searching for offsets of the length and the payload
    (0..diffs.length-1).each do |j|
      currByte = diffs[j]
      nextByte = diffs[j+1]
      prevByte = diffs[j-1]

      if j>0
        # Skip this if we compared these two bytes on the previous iteration
        next if prevByte.position == currByte.position
      end

      # Compare this byte and the following byte to identify length and buffer offsets
      lengthOffset.push(currByte.position) if isLengthOffset?(currByte,nextByte)
      bufferOffset.push(currByte.position) if isBufferOffset?(currByte,nextByte)
    end
  end

  payloadBytes = Base64.strict_encode64(emptyPayload).gsub(/\n/,"")
  if bufferOffset.length > 0
    results[payload]={"status": "dynamic", "lengthOffset": lengthOffset.uniq, "bufferOffset": bufferOffset.uniq, "bytes": payloadBytes }
  else
    #TODO: Turns out ysoserial doesn't have any static payloads.  Consider removing this.
    results[payload]={"status": "static", "bytes": payloadBytes }
  end
end

payloadCount = {}
payloadCount['skipped'] = 0
payloadCount['static']  = 0
payloadCount['dynamic'] = 0

results.each do |k,v|
  if v[:status] == "unsupported"
    payloadCount['skipped'] += 1
  elsif v[:status] == "static"
    payloadCount['static'] += 1
  elsif v[:status] == "dynamic"
    payloadCount['dynamic'] += 1
  end
end

puts JSON.generate(results)

STDERR.puts "DONE!  Successfully generated #{payloadCount['static']} static payloads and #{payloadCount['dynamic']} dynamic payloads.  Skipped #{payloadCount['skipped']} unsupported payloads."
