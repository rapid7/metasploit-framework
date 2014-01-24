# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_helper'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

#
# Utility methods and constants for dealing with most types of variables.
#
class  Util

  # Bring in some useful string manipulation utility functions
  include DLLHelper

  # Data type size info: http://msdn.microsoft.com/en-us/library/s3f49ktz(v=vs.80).aspx
  PRIMITIVE_TYPE_SIZES = {
    :int => 4,
    :__int8 => 1,
    :__int16 => 2,
    :__int32 => 4,
    :__int64 => 8,
    :bool => 1,
    :char => 1,
    :short => 2,
    :long => 4,
    :long_long => 8,
    :float => 4,
    :double => 8,
    :long_double => 8,
    :wchar_t => 2,
  }

  #
  # Maps a data type to its corresponding primitive or special type
  # +:pointer+.  Note, primitive types are mapped to themselves.
  #
  # typedef info: http://msdn.microsoft.com/en-us/library/aa383751(v=vs.85).aspx
  TYPE_DEFINITIONS = {
    ##
    # Primitives
    ##
    :int => :int,
    :__int8 => :__int8,
    :__int16 => :__int16,
    :__int32 => :__int32,
    :__int64 => :__int64,
    :bool => :bool,
    :char => :char,
    :short => :short,
    :long => :long,
    :long_long => :long_long,
    :float => :float,
    :double => :double,
    :long_double => :long_double,
    :wchar_t => :wchar_t,
    ##
    # Non-pointers
    ##
    #typedef WORD ATOM;
    :ATOM => :short,
    #typedef int BOOL;
    :BOOL => :int,
    #typedef BYTE BOOLEAN;
    :BOOLEAN => :char,
    #typedef unsigned char BYTE;
    :BYTE => :char,
    #typedef char CHAR;
    :CHAR => :char,
    #typedef DWORD COLORREF;
    :COLORREF => :long,
    #typedef unsigned long DWORD;
    :DWORD => :long,
    #typedef unsigned int DWORD32;
    :DWORD32 => :int,
    #typedef unsigned __int64 DWORD64;
    :DWORD64 => :__int64,
    #typedef float FLOAT;
    :FLOAT => :float,
    #typedef int HFILE;
    :HFILE => :int,
    #typedef LONG HRESULT;
    :HRESULT => :long,
    #typedef int INT;
    :INT => :int,
    #typedef signed int INT32;
    :INT32 => :int,
    #typedef signed __int64 INT64;
    :INT64 => :__int64,
    #typedef WORD LANGID;
    :LANGID => :short,
    #typedef DWORD LCID;
    :LCID => :long,
    #typedef DWORD LCTYPE;
    :LCTYPE => :long,
    #typedef DWORD LGRPID;
    :LGRPID => :long,
    #typedef long LONG;
    :LONG => :long,
    #typedef signed int LONG32;
    :LONG32 => :int,
    #typedef __int64 LONG64;
    :LONG64 => :__int64,
    #typedef PDWORD PLCID;
    :PLCID => :pointer,
    #typedef LPVOID SC_LOCK;
    :SC_LOCK => :pointer,
    #typedef short SHORT;
    :SHORT => :short,
    #typedef unsigned char UCHAR;
    :UCHAR => :char,
    #typedef unsigned int UINT;
    :UINT => :int,
    #typedef unsigned int UINT32;
    :UINT32 => :int,
    #typedef unsigned long ULONG;
    :ULONG => :long,
    #typedef unsigned int ULONG32;
    :ULONG32 => :int,
    #typedef unsigned __int64 ULONG64;
    :ULONG64 => :__int64,
    #typedef unsigned short USHORT;
    :USHORT => :short,
    #typedef wchar_t WCHAR;
    :WCHAR => :wchar_t,
    #typedef unsigned short WORD;
    :WORD => :short,
    ##
    # Pointers declared with *
    ##
    #typedef DWORD* LPCOLORREF;
    :LPCOLORREF => :pointer,
    #typedef void* LPCVOID;
    :LPCVOID => :pointer,
    #typedef WCHAR* LPCWSTR;
    :LPCWSTR => :pointer,
    #typedef DWORD* LPDWORD;
    :LPDWORD => :pointer,
    #typedef HANDLE* LPHANDLE;
    :LPHANDLE => :pointer,
    #typedef int* LPINT;
    :LPINT => :pointer,
    #typedef long* LPLONG;
    :LPLONG => :pointer,
    #typedef CHAR* LPSTR;
    :LPSTR => :pointer,
    #typedef void* LPVOID;
    :LPVOID => :pointer,
    #typedef WORD* LPWORD;
    :LPWORD => :pointer,
    #typedef WCHAR* LPWSTR;
    :LPWSTR => :pointer,
    #typedef BOOL* PBOOL;
    :PBOOL => :pointer,
    #typedef BOOLEAN* PBOOLEAN;
    :PBOOLEAN => :pointer,
    #typedef BYTE* PBYTE;
    :PBYTE => :pointer,
    #typedef CHAR* PCHAR;
    :PCHAR => :pointer,
    #typedef CHAR* PCSTR;
    :PCSTR => :pointer,
    #typedef WCHAR* PCWSTR;
    :PCWSTR => :pointer,
    #typedef DWORD* PDWORD;
    :PDWORD => :pointer,
    #typedef DWORDLONG* PDWORDLONG;
    :PDWORDLONG => :pointer,
    #typedef DWORD_PTR* PDWORD_PTR;
    :PDWORD_PTR => :pointer,
    #typedef DWORD32* PDWORD32;
    :PDWORD32 => :pointer,
    #typedef DWORD64* PDWORD64;
    :PDWORD64 => :pointer,
    #typedef FLOAT* PFLOAT;
    :PFLOAT => :pointer,
    #typedef HANDLE* PHANDLE;
    :PHANDLE => :pointer,
    #typedef HKEY* PHKEY;
    :PHKEY => :pointer,
    #typedef int* PINT;
    :PINT => :pointer,
    #typedef INT_PTR* PINT_PTR;
    :PINT_PTR => :pointer,
    #typedef INT32* PINT32;
    :PINT32 => :pointer,
    #typedef INT64* PINT64;
    :PINT64 => :pointer,
    #typedef LONG* PLONG;
    :PLONG => :pointer,
    #typedef LONGLONG* PLONGLONG;
    :PLONGLONG => :pointer,
    #typedef LONG_PTR* PLONG_PTR;
    :PLONG_PTR => :pointer,
    #typedef LONG32* PLONG32;
    :PLONG32 => :pointer,
    #typedef LONG64* PLONG64;
    :PLONG64 => :pointer,
    #typedef SHORT* PSHORT;
    :PSHORT => :pointer,
    #typedef SIZE_T* PSIZE_T;
    :PSIZE_T => :pointer,
    #typedef SSIZE_T* PSSIZE_T;
    :PSSIZE_T => :pointer,
    #typedef CHAR* PSTR;
    :PSTR => :pointer,
    #typedef TBYTE* PTBYTE;
    :PTBYTE => :pointer,
    #typedef TCHAR* PTCHAR;
    :PTCHAR => :pointer,
    #typedef UCHAR* PUCHAR;
    :PUCHAR => :pointer,
    #typedef UINT* PUINT;
    :PUINT => :pointer,
    #typedef UINT_PTR* PUINT_PTR;
    :PUINT_PTR => :pointer,
    #typedef UINT32* PUINT32;
    :PUINT32 => :pointer,
    #typedef UINT64* PUINT64;
    :PUINT64 => :pointer,
    #typedef ULONG* PULONG;
    :PULONG => :pointer,
    #typedef ULONGLONG* PULONGLONG;
    :PULONGLONG => :pointer,
    #typedef ULONG_PTR* PULONG_PTR;
    :PULONG_PTR => :pointer,
    #typedef ULONG32* PULONG32;
    :PULONG32 => :pointer,
    #typedef ULONG64* PULONG64;
    :PULONG64 => :pointer,
    #typedef USHORT* PUSHORT;
    :PUSHORT => :pointer,
    #typedef void* PVOID;
    :PVOID => :pointer,
    #typedef WCHAR* PWCHAR;
    :PWCHAR => :pointer,
    #typedef WORD* PWORD;
    :PWORD => :pointer,
    #typedef WCHAR* PWSTR;
    :PWSTR => :pointer,
    #typedef HANDLE HACCEL;
    :HACCEL => :pointer,
    ##
    #  Handles
    ##
    #typedef PVOID HANDLE;
    :HANDLE => :pointer,
    #typedef HANDLE HBITMAP;
    :HBITMAP => :pointer,
    #typedef HANDLE HBRUSH;
    :HBRUSH => :pointer,
    #typedef HANDLE HCOLORSPACE;
    :HCOLORSPACE => :pointer,
    #typedef HANDLE HCONV;
    :HCONV => :pointer,
    #typedef HANDLE HCONVLIST;
    :HCONVLIST => :pointer,
    #typedef HANDLE HDC;
    :HDC => :pointer,
    #typedef HANDLE HDDEDATA;
    :HDDEDATA => :pointer,
    #typedef HANDLE HDESK;
    :HDESK => :pointer,
    #typedef HANDLE HDROP;
    :HDROP => :pointer,
    #typedef HANDLE HDWP;
    :HDWP => :pointer,
    #typedef HANDLE HENHMETAFILE;
    :HENHMETAFILE => :pointer,
    #typedef HANDLE HFONT;
    :HFONT => :pointer,
    #typedef HANDLE HGDIOBJ;
    :HGDIOBJ => :pointer,
    #typedef HANDLE HGLOBAL;
    :HGLOBAL => :pointer,
    #typedef HANDLE HHOOK;
    :HHOOK => :pointer,
    #typedef HANDLE HICON;
    :HICON => :pointer,
    #typedef HANDLE HINSTANCE;
    :HINSTANCE => :pointer,
    #typedef HANDLE HKEY;
    :HKEY => :pointer,
    #typedef HANDLE HKL;
    :HKL => :pointer,
    #typedef HANDLE HLOCAL;
    :HLOCAL => :pointer,
    #typedef HANDLE HMENU;
    :HMENU => :pointer,
    #typedef HANDLE HMETAFILE;
    :HMETAFILE => :pointer,
    #typedef HANDLE HPALETTE;
    :HPALETTE => :pointer,
    #typedef HANDLE HPEN;
    :HPEN => :pointer,
    #typedef HANDLE HRGN;
    :HRGN => :pointer,
    #typedef HANDLE HRSRC;
    :HRSRC => :pointer,
    #typedef HANDLE HSZ;
    :HSZ => :pointer,
    #typedef HANDLE WINSTA;
    :WINSTA => :pointer,
    #typedef HANDLE HWND;
    :HWND => :pointer,
    #typedef HANDLE SC_HANDLE;
    :SC_HANDLE => :pointer,
    #typedef HANDLE SERVICE_STATUS_HANDLE;
    :SERVICE_STATUS_HANDLE => :pointer,
  }

  # param 'railgun' is a Railgun instance.
  # param 'platform' is a value like client.platform
  def initialize(railgun, platform)
    @railgun = railgun
    @is_64bit = is_64bit_platform?(platform)
  end

  #
  # Given a packed pointer, unpacks it according to architecture
  #
  def unpack_pointer(packed_pointer)
    if is_64bit
      # XXX: Only works if attacker and victim are like-endianed
      packed_pointer.unpack('Q')[0]
    else
      packed_pointer.unpack('V')[0]
    end
  end

  #
  # Returns true if +pointer+ will be considered a 'null' pointer.
  #
  # If +pointer+ is nil or 0, returns true
  # If +pointer+ is a String, if 0 after unpacking, returns true
  # false otherwise
  #
  # See #unpack_pointer
  #
  def is_null_pointer(pointer)
    if pointer.kind_of? String
      pointer = unpack_pointer(pointer)
    end

    return pointer.nil? || pointer == 0
  end

  #
  # Reads null-terminated unicode strings from memory.
  #
  # Given a pointer to a null terminated array of WCHARs, return a ruby
  # String. If +pointer+ is NULL (see #is_null_pointer) returns an empty
  # string.
  #
  def read_wstring(pointer, length = nil)
    # Return an empty string for null pointers
    if is_null_pointer(pointer)
      return ''
    end

    # If length not provided, use lstrlenW
    if length.nil?
      length = railgun.kernel32.lstrlenW(pointer)['return']
    end

    # Retrieve the array of characters
    chars = read_array(:WCHAR, length, pointer)

    # Concatenate the characters and convert to a ruby string
    str = uniz_to_str(chars.join(''))

    return str
  end

  def read_string(pointer, length=nil)
    if is_null_pointer(pointer)
      return ''
    end

    unless length
      length = railgun.kernel32.lstrlenA(pointer)['return']
    end

    chars = read_array(:CHAR, length, pointer)
    return chars.join('')
  end

  #
  # Read a given number of bytes from memory or from a provided buffer.
  #
  # If +buffer+ is not provided, read +size+ bytes from the client's memory.
  # If +buffer+ is provided, reads +size+ characters from the index of +address+.
  #
  def memread(address, size, buffer = nil)
    if buffer.nil?
      return railgun.memread(address, size)
    else
      return buffer[address .. (address + size - 1)]
    end
  end

  #
  # Read and unpack a pointer from the given buffer at a given offset
  #
  def read_pointer(buffer, offset = 0)
    unpack_pointer(buffer[offset, (offset + pointer_size)])
  end

  #
  # Reads data structures and several windows data types
  #
  def read_data(type, position, buffer = nil)
    if buffer.nil?
      buffer = memread(position, sizeof_type(type))
      position = 0
    end

    # If we're asked to read a data structure, deligate to read_struct
    if is_struct_type?(type)
      return read_struct(type, buffer, position)
    end

    # If the type is an array with a given size...
    #    BYTE[3] for example or BYTE[ENCRYPTED_PWLEN] or even PDWORD[23]
    if is_array_type?(type)
      # Separate the element type from the size of the array
      element_type, length = split_array_type(type)

      # Have read_array take care of the rest
      return read_array(element_type, length, position, buffer)
    end

    size = sizeof_type(type)
    raw  = memread(position, size, buffer)

    # read/unpack data for the types we have hard-coded support for
    case type
    when :LPWSTR
      # null-terminated string of 16-bit Unicode characters
      return read_wstring(read_pointer(raw))
    when :DWORD
      # Both on x86 and x64, DWORD is 32 bits
      return raw.unpack('V').first
    when :BOOL
      return raw.unpack('l').first == 1
    when :LONG
      return raw.unpack('l').first
    end

    #If nothing worked thus far, return it raw
    return raw
  end

  #
  # Read +length+ number of instances of +type+ from +bufptr+ .
  #
  # +bufptr+ is an index in +buffer+ or, if +buffer+ is nil, a memory address
  #
  def read_array(type, length, bufptr, buffer = nil)
    if length <= 0
      return []
    end

    size = sizeof_type(type)
    # Grab the bytes that the array consists of
    buffer = memread(bufptr, size * length, buffer)

    offset = 0

    1.upto(length).map do |n|
      data = read_data(type, offset, buffer)

      offset = offset + size

      data
    end
  end

  #
  # Construct the data structure described in +definition+ from +buffer+
  # starting from the index +offset+
  #
  def read_struct(definition, buffer, offset = 0)
    data = {}

    offsets = struct_offsets(definition, offset)

    definition.each do |mapping|
      key, data_type = mapping

      data[key] = read_data(data_type, offsets.shift, buffer)
    end

    data
  end


  # Returns true if the data type is a pointer, false otherwise
  def is_pointer_type?(type)
    return TYPE_DEFINITIONS[type] == :pointer
  end

  # Returns whether the given type represents an array of another type
  # For example BYTE[3], BYTE[ENCRYPTED_PWLEN], or even PDWORD[23]
  def is_array_type?(type)
    return type =~ /^\w+\[\w+\]$/ ? true : false
  end

  # Returns true if the type passed describes a data structure, false otherwise
  def is_struct_type?(type)
    return type.kind_of? Array
  end


  # Returns the pointer size for this architecture
  def pointer_size
    is_64bit ? 8 : 4
  end

  # Return the size, in bytes, of the given type
  def sizeof_type(type)
    if is_pointer_type?(type)
      return pointer_size
    end

    if type.kind_of? String
      if is_array_type?(type)
        element_type, length = split_array_type(type)
        return length * sizeof_type(element_type)
      else
        return sizeof_type(type.to_sym)
      end
    end

    if is_struct_type?(type)
      return sizeof_struct(type)
    end

    if TYPE_DEFINITIONS.has_key?(type)
      primitive = TYPE_DEFINITIONS[type]

      if primitive == :pointer
        return pointer_size
      end

      if PRIMITIVE_TYPE_SIZES.has_key?(primitive)
        return PRIMITIVE_TYPE_SIZES[primitive]
      else
        raise "Type #{type} was mapped to non-existent primitive #{primitive}"
      end
    end

    raise "Unable to determine size for type #{type}."
  end

  #
  # Calculates the size of +struct+ after alignment.
  #
  def sizeof_struct(struct)
    offsets = struct_offsets(struct, 0)
    last_data_size = sizeof_type(struct.last[1])
    size_no_padding = offsets.last + last_data_size

    return size_no_padding + calc_padding(size_no_padding)
  end

  #
  # Given a description of a data structure, returns an Array containing
  # the offset from the beginning for each subsequent element, taking into
  # consideration alignment and padding.
  #
  def struct_offsets(definition, offset)
    padding = 0
    offsets = []
    definition.each do |mapping|
      key, data_type = mapping
      if sizeof_type(data_type) > padding
        offset = offset + padding
      end

      offsets.push(offset)

      offset = offset + sizeof_type(data_type)
      padding = calc_padding(offset)
    end

    offsets
  end

  # http://en.wikipedia.org/wiki/Data_structure_alignment
  def required_alignment
    is_64bit ? 8 : 4
  end

  #
  # Number of bytes that needed to be added to be aligned.
  #
  def calc_padding(offset)
    align = required_alignment

    # If offset is not aligned...
    if (offset % align) != 0
      # Calculate padding needed to be aligned
      align - (offset & (align - 1))
    else
      0
    end
  end

  #
  # Given an explicit array definition (e.g. BYTE[23]) return size (e.g. 23) and
  # and +type+ (e.g. BYTE). If a constant is given, attempt to resolve it
  # that constant.
  #
  def split_array_type(type)
    if type =~ /^(\w+)\[(\w+)\]$/
      element_type = $1
      length = $2
      unless length =~ /^\d+$/
        length = railgun.const(length)
      end

      return element_type.to_sym, length.to_i
    else
      raise "Can not split non-array type #{type}"
    end
  end

  # Returns true if given platform has 64bit architecture
  # expects client.platform
  def is_64bit_platform?(platform)
    platform =~ /win64/
  end

  #
  # Evaluates a bit field, returning a hash representing the meaning and
  # state of each bit.
  #
  # Parameters:
  #   +value+:: a bit field represented by a Fixnum
  #   +mappings+:: { 'WINAPI_CONSTANT_NAME' => :descriptive_symbol, ... }
  #
  # Returns:
  #   { :descriptive_symbol => true/false, ... }
  #
  def judge_bit_field(value, mappings)
    flags = {}
    rg = railgun

    mappings.each do |constant_name, key|
      flags[key] = (value & rg.const(constant_name)) != 0
    end

    flags
  end

  protected

  attr_accessor :railgun, :is_64bit
end # Util
end # Railgun
end # Stdapi
end # Extensions
end # Meterpreter
end # Post
end # Rex
