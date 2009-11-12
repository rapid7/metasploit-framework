#!/usr/bin/env ruby


template = %Q|<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0"
     processorArchitecture="X86"
     name="%%NAME%%"
     type="win32"/>

  <!-- Identify the application security requirements. -->
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel
          level="highestAvailable"
          uiAccess="true"/>
        </requestedPrivileges>
       </security>
  </trustInfo>
</assembly>
|


dir = ARGV.shift() || exit
Dir.new(dir).entries.each do |name|
	next if name !~ /\.exe$/i
	temp = template.dup.gsub('%%NAME%%', name)
	File.open(File.join(dir, "#{name}.manifest"), "wb") do |fd|
		fd.write(temp)
	end
end
