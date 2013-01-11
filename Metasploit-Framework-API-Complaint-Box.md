### People rarely remember to handle `nil` as a return type of `send_request_cgi()`

calling `send_request_cgi()` can return either `nil` or a `Rex::Proto::Response` object, or raise an error. None of these outcomes are sufficiently documented, so it's not surprising nobody remembers to handle `nil`.
