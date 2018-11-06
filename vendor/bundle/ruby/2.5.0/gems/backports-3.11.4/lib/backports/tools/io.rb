require 'backports/tools/arguments'
module Backports
  # Used internally to combine {IO|File} options hash into mode (String or Integer)
  def self.combine_mode_and_option(mode = nil, options = Backports::Undefined)
    # Can't backport autoclose, {internal|external|}encoding
    mode, options = nil, mode if mode.respond_to?(:to_hash) && options == Backports::Undefined
    options = {} if options == nil || options == Backports::Undefined
    options = coerce_to_hash(options)
    if mode && options[:mode]
      raise ArgumentError, "mode specified twice"
    end
    mode ||= options[:mode] || "r"
    mode = try_convert(mode, String, :to_str) || try_convert(mode, Integer, :to_int) || mode
    if options[:textmode] || options[:binmode]
      text = options[:textmode] || (mode.is_a?(String) && mode =~ /t/)
      bin  = options[:binmode]  || (mode.is_a?(String) ? mode =~ /b/ : mode & File::Constants::BINARY != 0)
      if text && bin
        raise ArgumentError, "both textmode and binmode specified"
      end
      case
        when !options[:binmode]
        when mode.is_a?(String)
          mode.insert(1, "b")
        else
          mode |= File::Constants::BINARY
      end
    end
    mode
  end

  # Used internally to combine {IO|File} options hash into mode (String or Integer) and perm
  def self.combine_mode_perm_and_option(mode = nil, perm = Backports::Undefined, options = Backports::Undefined)
    mode, options = nil, mode if mode.respond_to?(:to_hash) && perm == Backports::Undefined
    perm, options = nil, perm if perm.respond_to?(:to_hash) && options == Backports::Undefined
    perm = nil if perm == Backports::Undefined
    options = {} if options == Backports::Undefined
    options = coerce_to_hash(options)
    if perm && options[:perm]
      raise ArgumentError, "perm specified twice"
    end
    [combine_mode_and_option(mode, options), perm || options[:perm]]
  end

  def self.write(binary, filename, string, offset, options)
    offset, options = nil, offset if offset.respond_to?(:to_hash) && options == Backports::Undefined
    options = {} if options == Backports::Undefined
    options = coerce_to_hash(options)
    File.open(filename, 'a+'){} if offset # insure existence
    options = {:mode => offset.nil? ? "w" : "r+"}.merge(options)
    args = options[:open_args] || [options]
    File.open(filename, *Backports.combine_mode_perm_and_option(*args)) do |f|
      f.binmode if binary && f.respond_to?(:binmode)
      f.seek(offset) unless offset.nil?
      f.write(string)
    end
  end
end
