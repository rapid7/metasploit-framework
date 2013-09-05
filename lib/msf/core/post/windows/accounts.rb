# -*- coding: binary -*-
module Msf
class Post
module Windows

module Accounts

  ##
  # delete_user(username, server_name = nil)
  #
  # Summary:
  #   Deletes a user account from the given server (or local if none given)
  #
  # Parameters
  #   username    - The username of the user to delete (not-qualified, e.g. BOB)
  #   server_name - DNS or NetBIOS name of remote server on which to delete user
  #
  # Returns:
  #   One of the following:
  #      :success          - Everything went as planned
  #      :invalid_server   - The server name provided was invalid
  #      :not_on_primary   - Operation allowed only on domain controller
  #      :user_not_found   - User specified does not exist on the given server
  #      :access_denied    - You do not have permission to delete the given user
  #
  #   OR nil if there was an exceptional windows error (example: ran out of memory)
  #
  # Caveats:
  #   nil is returned if there is an *exceptional* windows error. That error is printed.
  #   Everything other than ':success' signifies failure
  ##
  def delete_user(username, server_name = nil)
    deletion = client.railgun.netapi32.NetUserDel(server_name, username)

    #http://msdn.microsoft.com/en-us/library/aa370674.aspx
    case deletion['return']
    when 2221 # NERR_UserNotFound
      return :user_not_found
    when 2351 # NERR_InvalidComputer
      return :invalid_server
    when 2226 # NERR_NotPrimary
      return :not_on_primary
    when client.railgun.const('ERROR_ACCESS_DENIED')
      return :access_denied
    when 0
      return :success
    else
      error = deletion['GetLastError']
      if error != 0
        print_error "Unexpected Windows System Error #{error}"
      else
        # Uh... we shouldn't be here
        print_error "DeleteUser unexpectedly returned #{deletion['return']}"
      end
    end

    # If we got here, then something above failed
    return nil
  end


  ##
  # resolve_sid(sid, system_name = nil)
  #
  # Summary:
  #   Retrieves the name, domain, and type of account for the given sid
  #
  # Parameters:
  #   sid         - A SID string (e.g. S-1-5-32-544)
  #   system_name - Where to search. If nil, first local system then trusted DCs
  #
  # Returns:
  #   {
  #     :name   => account name (e.g. "SYSTEM")
  #     :domain => domain where the account name was found. May have values such as
  #                the work station's name, BUILTIN, NT AUTHORITY, or an empty string
  #     :type   => one of :user, :group, :domain, :alias, :well_known_group,
  #                :deleted_account, :invalid, :unknown, :computer
  #     :mapped => There was a mapping found for the SID
  #   }
  #
  #   OR nil if there was an exceptional windows error (example: ran out of memory)
  #
  # Caveats:
  #   If a valid mapping is not found, only { :mapped => false } will be returned
  #   nil is returned if there is an *exceptional* windows error. That error is printed.
  #   If an invalid system_name is provided, there will be a windows error and nil returned
  ##
  def resolve_sid(sid, system_name = nil)
    adv = client.railgun.advapi32;

    # Second param is the size of the buffer where the pointer will be written
    # In railgun, if you specify 4 bytes for a PDWORD it will grow to 8, as needed.
    conversion = adv.ConvertStringSidToSidA(sid, 4)

    # If the call failed, handle errors accordingly.
    unless conversion['return']
      error = conversion['GetLastError']

      case error
      when client.railgun.const('ERROR_INVALID_SID')
        # An invalid SID was supplied
        return { :type => :invalid, :mapped => false }
      else
        print_error "Unexpected windows error #{error}"
        return nil
      end
    end

    # A reference to the SID data structure. Generally needed when working with sids
    psid = conversion['pSid']

    # http://msdn.microsoft.com/en-us/library/aa379166(v=vs.85).aspx
    # TODO: The buffer sizes here need to be reviewed/adjusted/optimized
    lookup = adv.LookupAccountSidA(system_name, psid, 100, 100, 100, 100, 1)

    # We no longer need the sid so free it.
    # NOTE: We do not check to see if this call succeeded. Do we care?
    adv.FreeSid(psid)

    # If the call failed, handle errors accordingly.
    unless lookup['return']
      error = lookup['GetLastError']

      case error
      when client.railgun.const('ERROR_INVALID_PARAMETER')
        # Unless the railgun call is broken, this means revesion is wrong
        return { :type => :invalid }
      when client.railgun.const('ERROR_NONE_MAPPED')
        # There were no accounts associated with this SID
        return { :mapped => false }
      else
        print_error "Unexpected windows error #{error}"
        return nil
      end
    end

    # peUse is the enum "SID_NAME_USE"
    sid_type = lookup_SID_NAME_USE(lookup['peUse'].unpack('C')[0])

    return {
      :name   => lookup['Name'],
      :domain => lookup['ReferencedDomainName'],
      :type   => sid_type,
      :mapped => true
    }
  end

  private

  ##
  # Converts a WinAPI's SID_NAME_USE enum to a symbol
  # Symbols are (in order) :user, :group, :domain, :alias, :well_known_group,
  #                        :deleted_account, :invalid, :unknown, :computer
  ##
  def lookup_SID_NAME_USE(enum_value)
    [
      # SidTypeUser = 1
      :user,
      # SidTypeGroup,
      :group,
      #SidTypeDomain,
      :domain,
      #SidTypeAlias,
      :alias,
      #SidTypeWellKnownGroup,
      :well_known_group,
      #SidTypeDeletedAccount,
      :deleted_account,
      #SidTypeInvalid,
      :invalid,
      #SidTypeUnknown,
      :unknown,
      #SidTypeComputer,
      :computer,
      #SidTypeLabel
      :integrity_label
    ][enum_value - 1]
  end

  # Gets an impersonation token from the primary token.
  #
  # @return [Fixnum] the impersonate token handle identifier if success, nil if
  #	fails
  def get_imperstoken
    adv =  session.railgun.advapi32
    tok_all = "TOKEN_ASSIGN_PRIMARY |TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | "
    tok_all << "TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS"
    tok_all << " | TOKEN_ADJUST_DEFAULT"

    pid = session.sys.process.open.pid
    pr = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
    pt = adv.OpenProcessToken(pr.handle, tok_all, 4) #get handle to primary token
    it = adv.DuplicateToken(pt["TokenHandle"],2, 4) # get an impersonation token
    if it["return"] #if it fails return 0 for error handling
      return it["DuplicateTokenHandle"]
    else
      return nil
    end
  end

  # Gets the permissions granted from the Security Descriptor of a directory
  # to an access token.
  #
  # @param [String] dir the directory path
  # @param [Fixnum] token the access token
  # @return [String, nil] a String describing the permissions or nil
  def check_dir_perms(dir, token)
    adv =  session.railgun.advapi32
    si = "OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION"
    result = ""

    #define generic mapping structure
    gen_map = [0,0,0,0]
    gen_map = gen_map.pack("L")
    buffer_size = 500

    #get Security Descriptor for the directory
    f = adv.GetFileSecurityA(dir, si, buffer_size, buffer_size, 4)
    if (f['return'] and f["lpnLengthNeeded"] <= buffer_size)
      sd = f["pSecurityDescriptor"]
    elsif (f['GetLastError'] == 122) # ERROR_INSUFFICIENT_BUFFER
      f = adv.GetFileSecurityA(dir, si, f["lpnLengthNeeded"], f["lpnLengthNeeded"], 4)
    elsif (f['GetLastError'] == 2)
      vprint_error("The system cannot find the file specified: #{dir}")
      return nil
    else
      vprint_error("Unknown error - GetLastError #{f['GetLastError']}: #{dir}")
      return nil
    end

    #check for write access, called once to get buffer size
    a = adv.AccessCheck(sd, token, "ACCESS_READ | ACCESS_WRITE", gen_map, 0, 0, 4, 8)
    len = a["PrivilegeSetLength"]

    r = adv.AccessCheck(sd, token, "ACCESS_READ", gen_map, len, len, 4, 8)
    if !r["return"] then return nil end
    if r["GrantedAccess"] > 0 then result << "R" end

    w = adv.AccessCheck(sd, token, "ACCESS_WRITE", gen_map, len, len, 4, 8)
    if !w["return"] then return nil end
    if w["GrantedAccess"] > 0 then result << "W" end
  end

end # Accounts
end # Windows
end # Post
end # Msf
