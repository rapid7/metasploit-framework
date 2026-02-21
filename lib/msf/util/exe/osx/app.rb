module Msf::Util::EXE::OSX::App
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::OSX::Common
  
  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods

    # Create an OSX .app bundle containing the Mach-O executable provided in +exe+
    # to_osx_app
    #  
    # @param  opts [Hash] The options hash
    # @option opts [Hash] :exe_name (random) the name of the macho exe file (never seen by the user)
    # @option opts [Hash] :app_name (random) the name of the OSX app
    # @option opts [Hash] :hidden (true) hide the app when it is running
    # @option opts [Hash] :plist_extra ('') some extra data to shove inside the Info.plist file
    # @return      [String] zip archive containing an OSX .app directory
    def to_osx_app(exe, opts = {})
      exe_name    = opts.fetch(:exe_name) { Rex::Text.rand_text_alpha(8) }
      app_name    = opts.fetch(:app_name) { Rex::Text.rand_text_alpha(8) }
      hidden      = opts.fetch(:hidden, true)
      plist_extra = opts.fetch(:plist_extra, '')

      app_name.chomp!(".app")
      app_name += ".app"

      visible_plist = if hidden
        %Q|
        <key>LSBackgroundOnly</key>
        <string>1</string>
        |
      else
        ''
      end

      info_plist = %Q|
        <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
    <key>CFBundleExecutable</key>
    <string>#{exe_name}</string>
    <key>CFBundleIdentifier</key>
    <string>com.#{exe_name}.app</string>
    <key>CFBundleName</key>
    <string>#{exe_name}</string>#{visible_plist}
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    #{plist_extra}
  </dict>
  </plist>
      |

      zip = Rex::Zip::Archive.new
      zip.add_file("#{app_name}/", '')
      zip.add_file("#{app_name}/Contents/", '')
      zip.add_file("#{app_name}/Contents/Resources/", '')
      zip.add_file("#{app_name}/Contents/MacOS/", '')
      # Add the macho and mark it as executable
      zip.add_file("#{app_name}/Contents/MacOS/#{exe_name}", exe).last.attrs = 0o777
      zip.add_file("#{app_name}/Contents/Info.plist", info_plist)
      zip.add_file("#{app_name}/Contents/PkgInfo", 'APPLaplt')
      zip.pack
    end
  end
  
  class << self
    include ClassMethods
  end

end
