When a module fails, the `fail_with` method provides a standardized way to describe the reason for the failure.  The first parameter depends on the cause of the failure.

## Example uses

`modules/exploits/osx/local/sudo_password_bypass.rb` fails using `Failure::NotVulnerable` if the `check` method does not indicate that the target is indeed vulnerable:
```
  if check != CheckCode::Vulnerable
    fail_with Failure::NotVulnerable, 'Target is not vulnerable'
  end
```

`modules/exploits/multi/http/struts2_namespace_ognl.rb` fails using the `Failure::PayloadFailed` if the target's response does not include a string indicating that the payload successfully executed.  Alternatively, if the target responds with an HTTP error, the module invokes `fail_with` using the `Failure::UnexpectedReply` parameter:
```
  if r && r.headers && r.headers['Location'].split('/')[1] == success_string
    print_good("Payload successfully dropped and executed.")
  elsif r && r.headers['Location']
    vprint_error("RESPONSE: " + r.headers['Location'])
    fail_with(Failure::PayloadFailed, "Target did not successfully execute the request")
  elsif r && r.code == 400
    fail_with(Failure::UnexpectedReply, "Target reported an unspecified error while executing the payload")
  end
```

## Comprehensive list of `fail_with` parameters

The following are currently used `fail_with` parameters, and a brief description of common uses.

| `fail_with` parameter    | Reason for failure                                                    |
|--------------------------|-----------------------------------------------------------------------|
| Failure::BadConfig       | The user-provided parameters are invalid and must be corrected.       |
| Failure::Disconnected    | The target closed the connection forcibly.                            |
| Failure::NoAccess        | An attempt to authenticate failed, likely due to invalid credentials. |
| Failure::None            | The outcome for the module has already been met (eg. a privilege escalation is already in an elevated context) |
| Failure::NoTarget        | The specified TARGET or PAYLOAD variables are misconfigured or the target environment is unsupported. |
| Failure::NotFound        | A preexisting file or resource on target is missing.                  |
| Failure::NotVulnerable   | The target returned a response indicative of being patched or otherwise mitigated. |
| Failure::PayloadFailed   | A return code from payload execution indicates the payload did not execute or terminated unexpectedly. |
| Failure::TimeoutExpired  | The target did not respond to the connection request in a timely manner.  Check RHOSTS and RPORT, then consider increasing WFSDelay. |
| Failure::UnexpectedReply | The target responded in an entirely unexpected way, and may not be running the vulnerable service at all. |
| Failure::Unknown         | An entirely unexpected exception occurred, and the target may not be running the expected services at all. |
| Failure::Unreachable     | The host or service is not reachable, often indicated by a refused connection or ICMP "unreachable" message. |