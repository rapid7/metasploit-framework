# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
class Packet

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
require 'rex/text'

  UUID = Rex::Proto::DCERPC::UUID

  # Create a standard DCERPC BIND request packet
  def self.make_bind(uuid, vers, xfer_syntax_uuid=UUID.xfer_syntax_uuid, xfer_syntax_vers=UUID.xfer_syntax_vers)

    # Process the version strings ("1.0", 1.0, "1", 1)
    bind_vers_maj, bind_vers_min = UUID.vers_to_nums(vers)
    xfer_vers_maj, xfer_vers_min = UUID.vers_to_nums(xfer_syntax_vers)

    if UUID.is? xfer_syntax_uuid
      xfer_syntax_uuid = UUID.uuid_pack(xfer_syntax_uuid)
    end

    # Create the bind request packet
    buff =
    [
      5,      # major version 5
      0,      # minor version 0
      11,     # bind type
      3,      # flags
      0x10000000,  # data representation
      72,     # frag length
      0,      # auth length
      0,      # call id
      5840,   # max xmit frag
      5840,   # max recv frag
      0,      # assoc group
      1,      # num ctx items
      0,      # context id
      1,      # num trans items
      UUID.uuid_pack(uuid),   # interface uuid
      bind_vers_maj,       # interface major version
      bind_vers_min,       # interface minor version
      xfer_syntax_uuid,  # transfer syntax
      xfer_vers_maj,       # syntax major version
      xfer_vers_min,       # syntax minor version
    ].pack('CCCCNvvVvvVVvvA16vvA16vv')

    return buff, 0
  end

  # Create an obfuscated DCERPC BIND request packet
  def self.make_bind_fake_multi(uuid, vers, bind_head=0, bind_tail=0)

    bind_head = bind_head.to_i
    bind_tail = bind_tail.to_i
    bind_head = rand(6)+10 if bind_head == 0
    bind_tail = rand(4)+1 if bind_head == 0

    u = Rex::Proto::DCERPC::UUID

    # Process the version strings ("1.0", 1.0, "1", 1)
    bind_vers_maj, bind_vers_min = UUID.vers_to_nums(vers)
    xfer_vers_maj, xfer_vers_min = UUID.vers_to_nums(UUID.xfer_syntax_vers)

    bind_total = bind_head + bind_tail + 1
    bind_size  = (bind_total * 44) + 28
    real_ctx, ctx = 0, 0

    # Create the header of the bind request
    data =
    [
      5,      # major version 5
      0,      # minor version 0
      11,     # bind type
      3,      # flags
      0x10000000,  # data representation
      bind_size,   # frag length
      0,      # auth length
      0,      # call id
      5840,   # max xmit frag
      5840,   # max recv frag
      0,      # assoc group
      bind_total,  # num ctx items
    ].pack('CCCCNvvVvvVV')

    # Generate the fake UUIDs prior to the real one
    1.upto(bind_head) do ||
      # Generate some random UUID and versions
      rand_uuid = Rex::Text.rand_text(16)
      rand_imaj = rand(6)
      rand_imin = rand(4)

      data +=
      [
        ctx,        # context id
        1,          # num trans items
        rand_uuid,  # interface uuid
        rand_imaj,  # interface major version
        rand_imin,  # interface minor version
        UUID.xfer_syntax_uuid,  # transfer syntax
        xfer_vers_maj,       # syntax major version
        xfer_vers_min,       # syntax minor version
      ].pack('vvA16vvA16vv')
      ctx += 1
    end

    # Stuff the real UUID onto the end of the buffer
    real_ctx = ctx;
    data +=
    [
      ctx,      # context id
      1,        # num trans items
      UUID.uuid_pack(uuid),   # interface uuid
      bind_vers_maj,       # interface major version
      bind_vers_min,       # interface minor version
      UUID.xfer_syntax_uuid,  # transfer syntax
      xfer_vers_maj,       # syntax major version
      xfer_vers_min,       # syntax minor version
    ].pack('vvA16vvA16vv')
    ctx += 1


    # Generate the fake UUIDs after the real one
    1.upto(bind_tail) do ||
      # Generate some random UUID and versions
      rand_uuid = Rex::Text.rand_text(16)
      rand_imaj = rand(6)
      rand_imin = rand(4)

      data +=
      [
        ctx,        # context id
        1,          # num trans items
        rand_uuid,  # interface uuid
        rand_imaj,  # interface major version
        rand_imin,  # interface minor version
        UUID.xfer_syntax_uuid,  # transfer syntax
        xfer_vers_maj,       # syntax major version
        xfer_vers_min,       # syntax minor version
      ].pack('vvA16vvA16vv')
      ctx += 1
    end

    # Return both the bind packet and the real context_id
    return data, real_ctx
  end

  # Create a standard DCERPC ALTER_CONTEXT request packet
  def self.make_alter_context(uuid, vers)
    u = Rex::Proto::DCERPC::UUID

    # Process the version strings ("1.0", 1.0, "1", 1)
    bind_vers_maj, bind_vers_min = UUID.vers_to_nums(vers)
    xfer_vers_maj, xfer_vers_min = UUID.vers_to_nums(UUID.xfer_syntax_vers)

    buff =
    [
      5,      # major version 5
      0,      # minor version 0
      14,     # alter context
      3,      # flags
      0x10000000,     # data representation
      72,     # frag length
      0,      # auth length
      0,      # call id
      5840,   # max xmit frag
      5840,   # max recv frag
      0,      # assoc group
      1,      # num ctx items
      0,      # context id
      1,      # num trans items
      UUID.uuid_pack(uuid),   # interface uuid
      bind_vers_maj,       # interface major version
      bind_vers_min,       # interface minor version
      UUID.xfer_syntax_uuid,  # transfer syntax
      xfer_vers_maj,       # syntax major version
      xfer_vers_min,       # syntax minor version
    ].pack('CCCCNvvVvvVVvvA16vvA16vv')
  end


  # Used to create a piece of a DCERPC REQUEST packet
  def self.make_request_chunk(flags=3, opnum=0, data="", ctx=0, object_id = '')

    flags = flags.to_i
    opnum = opnum.to_i
    ctx   = ctx.to_i

    dlen = data.length
    flen = dlen + 24

    use_object = 0

    object_str = ''

    if object_id.size > 0
      flags |= 0x80
      flen = flen + 16
      object_str = UUID.uuid_pack(object_id)
    end

    buff =
    [
      5,      # major version 5
      0,      # minor version 0
      0,      # request type
      flags,  # flags
      0x10000000,     # data representation
      flen,   # frag length
      0,      # auth length
      0,      # call id
      dlen,   # alloc hint
      ctx,    # context id
      opnum,  # operation number
    ].pack('CCCCNvvVVvv') + object_str + data
  end

  # Used to create standard DCERPC REQUEST packet(s)
  def self.make_request(opnum=0, data="", size=data.length, ctx=0, object_id = '')

    opnum = opnum.to_i
    size  = [4000, size.to_i].min
    ctx   = ctx.to_i

    chunks, frags = [], []
    ptr = 0

    # Break the request into fragments of 'size' bytes
    while ptr < data.length
      chunks.push( data[ ptr, size ] )
      ptr += size
    end

    # Process requests with no stub data
    if chunks.length == 0
      frags.push( make_request_chunk(3, opnum, '', ctx, object_id) )
      return frags
    end

    # Process requests with only one fragment
    if chunks.length == 1
      frags.push( make_request_chunk(3, opnum, chunks[0], ctx, object_id) )
      return frags
    end

    # Create the first fragment of the request
    frags.push( make_request_chunk(1, opnum, chunks.shift, ctx, object_id) )

    # Create all of the middle fragments
    while chunks.length != 1
      frags.push( make_request_chunk(0, opnum, chunks.shift, ctx, object_id) )
    end

    # Create the last fragment of the request
    frags.push( make_request_chunk(2, opnum, chunks.shift, ctx, object_id) )

    return frags
  end

end
end
end
end
