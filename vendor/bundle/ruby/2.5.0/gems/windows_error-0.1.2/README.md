# WindowsError
[![Gem Version](https://badge.fury.io/rb/windows_error.svg)](http://badge.fury.io/rb/windows_error)
[![Build Status](https://travis-ci.org/rapid7/windows_error.svg)](https://travis-ci.org/rapid7/windows_error)
[![Code Climate](https://codeclimate.com/github/rapid7/windows_error/badges/gpa.svg)](https://codeclimate.com/github/rapid7/windows_error)
[![Coverage Status](https://coveralls.io/repos/rapid7/windows_error/badge.svg?branch=master)](https://coveralls.io/r/rapid7/windows_error?branch=master)
[![PullReview stats](https://www.pullreview.com/github/rapid7/windows_error/badges/master.svg?)](https://www.pullreview.com/github/rapid7/windows_error/reviews/master)


The WindowsError gem provides an easily accessible reference for standard Windows API Error Codes. It allows you to do comparisons as well as direct lookups of error codes to translate the numerical value returned by the API, into a meaningful and human readable message. WindowsError currently supports [NTSTATUS](https://msdn.microsoft.com/en-us/library/cc231200.aspx) and [Win32 Error Codes](https://msdn.microsoft.com/en-us/library/cc231199.aspx). See [Windows Error Codes](https://msdn.microsoft.com/en-us/library/cc231196.aspx) for more details on all Windows Error Codes.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'windows_error'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install windows_error

## Usage

###Looking up an NTSTATUS code
Code:

```ruby
require 'windows_error/nt_status'
return_value_from_api_call = 0x00000000
error_codes = WindowsError::NTStatus.find_by_retval(return_value_from_api_call)
error_codes.each do |error_code|
	puts "#{error_code.name}: #{error_code.description}"
end
```

Output:

```
STATUS_SUCCESS: The operation completed successfully.
STATUS_WAIT_0: The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.
```

###Looking up a Win32 code
Code:

```ruby
require 'windows_error/win32'
return_value_from_api_call = 0x00000002
error_codes = WindowsError::Win32.find_by_retval(return_value_from_api_call)
error_codes.each do |error_code|
	puts "#{error_code.name}: #{error_code.description}"
end
```

Output:

```
ERROR_FILE_NOT_FOUND: The system cannot find the file specified.
```

###Testing Equality

```ruby
require 'windows_error/win32'
return_value_from_api_call = 0x00000002
return_value_from_api_call == WindowsError::Win32::ERROR_FILE_NOT_FOUND #=> true
WindowsError::Win32::ERROR_FILE_NOT_FOUND == return_value_from_api_call #=> true
0x00000001 == WindowsError::Win32::ERROR_FILE_NOT_FOUND #=> false
```



## Contributing

1. Fork it ( https://github.com/[my-github-username]/windows_error/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
