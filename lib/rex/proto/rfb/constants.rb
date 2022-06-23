# -*- coding: binary -*-

##
#
# RFB protocol support
#
# by Joshua J. Drake <jduck>
#
# Based on:
# vnc_auth_none contributed by Matteo Cantoni <goony[at]nothink.org>
# vnc_auth_login contributed by carstein <carstein.sec[at]gmail.com>
#
##

module Rex
  module Proto
    module RFB::Constants
      DefaultPort = 5900

      # Version information
      MajorVersions = [3, 4, 5]
      # NOTE: We will emulate whatever minor version the server reports.

      # Security types https://datatracker.ietf.org/doc/html/rfc6143#section-8.1.2
      # https://www.iana.org/assignments/rfb/rfb.xhtml
      class AuthType
        Invalid = 0
        None = 1
        VNC = 2
        # RealVNC has 3-15 registered
        RealVNC_3 = 3
        RealVNC_4 = 4
        RA2 = 5
        RA2ne = 6
        RealVNC_7 = 7
        RealVNC_8 = 8
        RealVNC_9 = 9
        RealVNC_10 = 10
        RealVNC_11 = 11
        RealVNC_12 = 12
        RealVNC_13 = 13
        RealVNC_14 = 14
        RealVNC_15 = 15
        Tight = 16
        Ultra = 17
        TLS = 18
        VeNCrypt = 19 # In TigerVNC this is used when one of the following options is specified: Plain, TLSNone, TLSVnc, TLSPlain, X509Vnc, X509Plain
        GtkVncSasl = 20
        MD5Hash = 21
        ColinDeanXVP = 22
        SecureTunnel = 23
        IntegratedSSH = 24
        ARD = 30
        # Apple has 31-35 registered, but no details on what these are. 36 is not registered but seems to be used by Apple
        Apple_31 = 31
        Apple_32 = 32
        Apple_33 = 33
        Apple_34 = 34
        MacOSX_35 = 35
        AppleUnknown_36 = 36
        # 116 has been observed in the wild in the following combo: Ultra, Unknown: 116, VNC
        RealVNC_128 = 128
        RealVNC_or_TightUnixLoginAuth = 129
        RealVNC_130 = 130
        RealVNC_131 = 131
        RealVNC_132 = 132
        RealVNC_133 = 133
        RealVNC_134 = 134
        RealVNC_192 = 192
        MSLOGON = 0xfffffffa

        def self.to_s(num)
          constants.each do |c|
            return c.to_s if const_get(c) == num
          end
          "Unknown: #{num}"
        end
      end
    end
  end
end
