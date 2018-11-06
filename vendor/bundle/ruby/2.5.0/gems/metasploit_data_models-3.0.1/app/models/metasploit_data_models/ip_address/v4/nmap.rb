# Nmap's octet range format composed of segments of comma separated list of segment numbers and segment number ranges.
#
# @example Nmap octect range format
#   # equivalent to ['1.5.6.7', '3.5.6.7', '4.5.6.7']
#   '1,3-4.5.6.7'
#
# @see http://nmap.org/book/man-target-specification.html
class MetasploitDataModels::IPAddress::V4::Nmap < MetasploitDataModels::IPAddress::V4::Segmented
  #
  # Segments
  #

  segment class_name: 'MetasploitDataModels::IPAddress::V4::Segment::Nmap::List'
end