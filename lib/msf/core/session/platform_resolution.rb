module Msf
    module Sessions
      module PlatformResolution
  
        # Analyzes a shell banner to determine the underlying OS platform
        def self.get_platform_from_banner(banner)
          return nil if banner.blank?
  
          case banner
          when /Microsoft Windows \[Version /i, /Microsoft Windows XP \[Version /i, /Copyright Microsoft Corp/i, /Microsoft\(R\) Windows NT\(TM\)/i
            'windows'
          when /Linux/i
            'linux'
          when /Darwin/i, /Mac OS/i
            'osx'
          when /SunOS/i
            'solaris'
          when /BSD/i
            'bsd'
          when /HP-UX/i
            'hpux'
          when /AIX/i
            'aix'
          when /IRIX/i
            'irix'
          else
            nil
          end
        end
  
      end
    end
  end