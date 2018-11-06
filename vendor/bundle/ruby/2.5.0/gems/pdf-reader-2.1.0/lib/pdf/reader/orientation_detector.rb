# coding: utf-8

class PDF::Reader
  # Small util class for detecting the orientation of a single PDF page. Accounts
  # for any page rotation that is in place.
  #
  #     OrientationDetector.new(:MediaBox => [0,0,612,792]).orientation
  #     => "portrait"
  #
  class OrientationDetector
    def initialize(attributes)
      @attributes = attributes
    end

    def orientation
      @orientation ||= detect_orientation
    end

    private

    def detect_orientation
      llx,lly,urx,ury = @attributes[:MediaBox]
      rotation        = @attributes[:Rotate].to_i
      width           = urx.to_i - llx.to_i
      height          = ury.to_i - lly.to_i
      if width > height
        [0,180].include?(rotation) ? 'landscape' : 'portrait'
      else
        [0,180].include?(rotation) ? 'portrait' : 'landscape'
      end
    end
  end
end
