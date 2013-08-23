module OSXRubyDLHelpers
  def osx_ruby_dl_header
    <<-EOS
  require 'dl'
  require 'dl/import'

  #### Patches to DL (for compatibility between 1.8->1.9)

  Importer = if defined?(DL::Importer) then DL::Importer else DL::Importable end

  def ruby_1_9_or_higher?
    RUBY_VERSION.to_f >= 1.9
  end

  def malloc(size)
    if defined?(DL::CPtr)
      DL::CPtr.malloc(size)
    else
      DL::malloc(size)
    end
  end

  # the old Ruby Importer defaults methods to downcase every import
  # This is annoying, so we'll patch with method_missing
  if not ruby_1_9_or_higher?
    module DL
      module Importable
        def method_missing(meth, *args, &block)
          str = meth.to_s
          lower = str[0,1].downcase + str[1..-1]
          if self.respond_to? lower
            self.send lower, *args
          else
            super
          end
        end
      end
    end
  end
  EOS
  end

  def osx_capture_media(opts)
    capture_code = <<-EOS
#{osx_ruby_dl_header}

options = {
  :action => '#{opts[:action]}', # or list|snapshot|record
  :snap_filetype => '#{opts[:snap_filetype]}', # jpg|png|gif|tiff|bmp
  :audio_enabled => #{opts[:audio_enabled]},
  :video_enabled => #{opts[:video_enabled]},
  :num_chunks => #{opts[:num_chunks]}, # wachawa!
  :chunk_len => #{opts[:chunk_len]}, # save chunks every 5 seconds
  :video_device => #{opts[:video_device]}, # automatic
  :audio_device => #{opts[:audio_device]},
  :snap_jpg_compression => #{opts[:snap_jpg_compression]}, # compression ratio (between 0 & 1), JPG ONLY
  :video_compression => '#{opts[:video_compression]}',
  :audio_compression => '#{opts[:audio_compression]}',
  :record_file => '#{opts[:record_file]}',
  :snap_file => '#{opts[:snap_file]}'
}

RUN_LOOP_STEP = 0.1 # "tick" duration for spinning NSRunLoop

# NSTIFFFileType  0 
# NSBMPFileType   1
# NSGIFFileType   2
# NSJPEGFileType  3
# NSPNGFileType   4 
SNAP_FILETYPES = %w(tiff bmp gif jpg png)

snap_filetype_index = SNAP_FILETYPES.index(options[:snap_filetype].to_s)

require 'fileutils'
FileUtils.mkdir_p File.dirname(options[:record_file])
FileUtils.mkdir_p File.dirname(options[:snap_file])

#### Helper methods for objc message passing

if not ruby_1_9_or_higher?
  # ruby < 1.9 freaks when you send int -> void* or flout -> void*
  #  so we have to reload the lib into separate modules with different
  #  exported typedefs, and patch objc_call to do our own typechecking.
  # this can probably be done better.
  module LibCWithInt
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, int, int)'
  end
  module LibCWithFloat
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, double, double)'
  end
  module LibCWithVoidPtrInt
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, void*, int)'
  end
  module LibCWithIntVoidPtr
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, int, void*)'
  end
end


def objc_call(instance, method, arg=nil, arg2=nil)
  # ruby < 1.9 freaks when you send int -> void* or flout -> void*
  # so we have to reload the lib into a separate with different exported typedefs,
  #  and call
  if not ruby_1_9_or_higher? and arg.kind_of?(Integer)
    if not arg2.kind_of?(Integer) and not arg2.nil?
      LibCWithIntVoidPtr.objc_msgSend(instance, LibCWithIntVoidPtr.sel_getUid(method), arg||0, arg2)
    else
      LibCWithInt.objc_msgSend(instance, LibCWithInt.sel_getUid(method), arg||0, arg2||0)
    end
  elsif not ruby_1_9_or_higher? and arg2.kind_of?(Integer)
    LibCWithVoidPtrInt.objc_msgSend(instance, LibCWithVoidPtrInt.sel_getUid(method), arg||0, arg2)
  elsif not ruby_1_9_or_higher? and arg.kind_of?(Float)
    LibCWithFloat.objc_msgSend(instance, LibCWithFloat.sel_getUid(method), arg||0.0, arg2||0.0)
  else
    QTKit.objc_msgSend(instance, QTKit.sel_getUid(method), arg, arg2)
  end
end

def objc_call_class(klass, method, arg=nil, arg2=nil)
  objc_call(QTKit.objc_getClass(klass), QTKit.sel_getUid(method), arg, arg2)
end

def nsstring(str)
  objc_call(objc_call(objc_call_class(
    'NSString', 'alloc'),
    'initWithCString:', str), 
    'autorelease')
end


#### External dynamically linked code

VID_TYPE = 'vide'
MUX_TYPE = 'muxx'
AUD_TYPE = 'soun'

module QTKit
  extend Importer
  dlload 'QTKit.framework/QTKit'
  extern 'void *objc_msgSend(void *, void *, void *, void*)'
  extern 'void *sel_getUid(void*)'
  extern 'void *objc_getClass(void *)'
end

#### Actual Webcam code
autorelease_pool = objc_call_class('NSAutoreleasePool', 'new')

vid_type = nsstring(VID_TYPE)
mux_type = nsstring(MUX_TYPE)
aud_type = nsstring(AUD_TYPE)

devices_ref = objc_call_class('QTCaptureDevice', 'inputDevices')
device_count = objc_call(devices_ref, 'count').to_i
if device_count.zero? and not options[:actions] =~ /list/i
  raise "Invalid device. Check devices with `set ACTION LIST`. Exiting."
  exit
end

device_enum = objc_call(devices_ref, 'objectEnumerator')
devices = (0...device_count).
  map { objc_call(device_enum, 'nextObject') }.
  select do |device|
    vid = objc_call(device, 'hasMediaType:', vid_type).to_i > 0
    mux = objc_call(device, 'hasMediaType:', mux_type).to_i > 0
    vid or mux
  end

device_enum = objc_call(devices_ref, 'objectEnumerator')
audio_devices = (0...device_count).
  map { objc_call(device_enum, 'nextObject') }.
  select { |d| objc_call(d, 'hasMediaType:', aud_type).to_i > 0 }

def device_names(devices)
  devices.
    map { |device| objc_call(device, 'localizedDisplayName') }.
    map { |name| objc_call(name, 'UTF8String') }.
    map(&:to_s)
end

def device_stati(devices)
  devices.
    map { |d| objc_call(d, 'isInUseByAnotherApplication').to_i > 0 }.
    map { |b| if b then 'BUSY' else 'AVAIL' end }
end

def print_devices(devices)
  device_names(devices).zip(device_stati(devices)).each_with_index do |d, i|
    puts "\#{i}.  \#{d[0]} [\#{d[1]}]"
  end
end

def print_compressions(type)
  compressions = objc_call_class('QTCompressionOptions',
    'compressionOptionsIdentifiersForMediaType:', type)
  count = objc_call(compressions, 'count').to_i
  if count.zero?
    puts "No supported compression types found."
  else
    comp_enum = objc_call(compressions, 'objectEnumerator')
    puts((0...count).
      map { objc_call(comp_enum, 'nextObject') }.
      map { |c| objc_call(c, 'UTF8String').to_s }.
      join("\n")
    )
  end
end

def use_audio?(options)
  options[:audio_enabled] and options[:action].to_s == 'record'
end

def use_video?(options)
  (options[:video_enabled] and options[:action].to_s == 'record') or options[:action].to_s == 'snapshot'
end

if options[:action].to_s == 'list'
  if options[:video_enabled]
    puts "===============\nVideo Devices:\n===============\n"
    print_devices(devices)
    puts "\nAvailable video compression types:\n\n"
    print_compressions(vid_type)
  end
  puts "\n===============\nAudio Devices:\n===============\n"
  print_devices(audio_devices)
  puts "\nAvailable audio compression types:\n\n"
  print_compressions(aud_type)
  exit
end

# Create a session to add I/O to
session = objc_call_class('QTCaptureSession', 'new')

# open the AV devices
if use_video?(options)
  video_device = devices[options[:video_device]]
  if not objc_call(video_device, 'open:', nil).to_i > 0
    raise 'Failed to open video device'
  end
  input = objc_call_class('QTCaptureDeviceInput', 'alloc')
  input = objc_call(input, 'initWithDevice:', video_device)
  objc_call(session, 'addInput:error:', input, nil)
end

if use_audio?(options)
  # open the audio device
  audio_device = audio_devices[options[:audio_device]]
  if not objc_call(audio_device, 'open:', nil).to_i > 0
    raise 'Failed to open audio device'
  end
  input = objc_call_class('QTCaptureDeviceInput', 'alloc')
  input = objc_call(input, 'initWithDevice:', audio_device)
  objc_call(session, 'addInput:error:', input, nil)
end

# initialize file output
record_file = options[:record_file]
output = objc_call_class('QTCaptureMovieFileOutput', 'new')
file_url = objc_call_class('NSURL', 'fileURLWithPath:', nsstring(record_file))
objc_call(output, 'recordToOutputFileURL:', file_url)
objc_call(session, 'addOutput:error:', output, nil)

# set up video/audio compression options
connection = nil
connection_enum = objc_call(objc_call(output, 'connections'), 'objectEnumerator')

while (connection = objc_call(connection_enum, 'nextObject')).to_i > 0
  media_type = objc_call(connection, 'mediaType')

  compress_opts = if objc_call(media_type, 'isEqualToString:', vid_type).to_i > 0 ||
                     objc_call(media_type, 'isEqualToString:', mux_type).to_i > 0 
    objc_call_class('QTCompressionOptions', 'compressionOptionsWithIdentifier:', 
      nsstring(options[:video_compression]))
  elsif use_audio?(options) and objc_call(media_type, 'isEqualToString:', aud_type).to_i > 0
    objc_call_class('QTCompressionOptions', 'compressionOptionsWithIdentifier:', 
      nsstring(options[:audio_compression]))
  end

  unless compress_opts.to_i.zero?
    objc_call(output, 'setCompressionOptions:forConnection:', compress_opts, connection)
  end
end

# start capturing from the webcam
objc_call(session, 'startRunning')

# we use NSRunLoop, which allows QTKit to spin its thread? somehow it is needed.
run_loop = objc_call_class('NSRunLoop', 'currentRunLoop')

# wait until at least one frame has been captured
while objc_call(output, 'recordedFileSize').to_i < 1
  time = objc_call(objc_call_class('NSDate', 'new'), 'autorelease')
  objc_call(run_loop, 'runUntilDate:', objc_call(time, 'dateByAddingTimeInterval:', RUN_LOOP_STEP))
end

if options[:action] == 'record' # record in a loop for options[:record_len] seconds
  curr_chunk = 0
  last_roll = Time.now
  # wait until at least one frame has been captured
  while curr_chunk < options[:num_chunks]
    time = objc_call(objc_call_class('NSDate', 'new'), 'autorelease')
    objc_call(run_loop, 'runUntilDate:', objc_call(time, 'dateByAddingTimeInterval:', RUN_LOOP_STEP))

    if Time.now - last_roll > options[:chunk_len].to_i # roll that movie file
      base = File.basename(record_file, '.*') # returns it with no extension
      num = ((base.match(/\\d+$/)||['0'])[0].to_i+1).to_s
      ext = File.extname(record_file) || 'o'
      record_file = File.join(File.dirname(record_file), base+num+'.'+ext)

      # redirect buffer output to new file path
      file_url = objc_call_class('NSURL', 'fileURLWithPath:', nsstring(record_file))
      objc_call(output, 'recordToOutputFileURL:', file_url)
      # remember we hit a chunk
      last_roll = Time.now
      curr_chunk += 1
    end
  end
end

# stop recording and stop session
objc_call(output, 'recordToOutputFileURL:', nil)
objc_call(session, 'stopRunning')

# give QTKit some time to write to file
objc_call(run_loop, 'runUntilDate:', objc_call(time, 'dateByAddingTimeInterval:', RUN_LOOP_STEP))

if options[:action] == 'snapshot' # user wants a snapshot
  # read captured movie file into QTKit
  dict = objc_call_class('NSMutableDictionary', 'dictionary')
  objc_call(dict, 'setObject:forKey:', nsstring('NSImage'), nsstring('QTMovieFrameImageType'))
  # grab a frame image from the move
  m = objc_call_class('QTMovie', 'movieWithFile:error:', nsstring(options[:record_file]), nil)
  img = objc_call(m, 'currentFrameImage')
  # set compression options
  opts = objc_call_class('NSDictionary', 'dictionaryWithObject:forKey:',
    objc_call_class('NSNumber', 'numberWithFloat:', options[:snap_jpg_compression]),
    nsstring('NSImageCompressionFactor')
  )
  # convert to desired format
  bitmap = objc_call(objc_call(img, 'representations'), 'objectAtIndex:', 0)
  data = objc_call(bitmap, 'representationUsingType:properties:', snap_filetype_index, opts)
  objc_call(data, 'writeToFile:atomically:', nsstring(options[:snap_file]), 0)

  objc_call(run_loop, 'runUntilDate:', objc_call(time, 'dateByAddingTimeInterval:', RUN_LOOP_STEP))

  # # delete the original movie file
  File.delete(options[:record_file])
end

objc_call(autorelease_pool, 'drain')

EOS
    if opts[:action] == 'record'
      capture_code = %Q|
        cpid = fork do
          #{capture_code}
        end
        Process.detach(cpid)
        puts cpid
|
    end
    capture_code
  end
end