/*
 *  Copyright (C) 2000-2006 Constantin Kaplinsky. All Rights Reserved.
 *  Copyright (C) 2000 Tridia Corporation. All Rights Reserved.
 *  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
 *
 *  This is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this software; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 *  USA.
 */

/*
 * rfbproto.h - header file for the RFB protocol, versions 3.3, 3.7 and 3.7t,
 * 3.8 and 3.8t ("t" suffix denotes TightVNC protocol extensions enabled)
 *
 * Uses types CARD<n> for an n-bit unsigned integer, INT<n> for an n-bit signed
 * integer (for n = 8, 16 and 32).
 *
 * All multiple byte integers are in big endian (network) order (most
 * significant byte first).  Unless noted otherwise there is no special
 * alignment of protocol structures.
 *
 *
 * Once the initial handshaking is done, all messages start with a type byte,
 * (usually) followed by message-specific data.  The order of definitions in
 * this file is as follows:
 *
 *  (1) Structures used in several types of message.
 *  (2) Structures used in the initial handshaking.
 *  (3) Message types.
 *  (4) Encoding types.
 *  (5) For each message type, the form of the data following the type byte.
 *      Sometimes this is defined by a single structure but the more complex
 *      messages have to be explained by comments.
 */


/*****************************************************************************
 *
 * Structures used in several messages
 *
 *****************************************************************************/

/*-----------------------------------------------------------------------------
 * Structure used to specify a rectangle.  This structure is a multiple of 4
 * bytes so that it can be interspersed with 32-bit pixel data without
 * affecting alignment.
 */

typedef struct _rfbRectangle {
    CARD16 x;
    CARD16 y;
    CARD16 w;
    CARD16 h;
} rfbRectangle;

#define sz_rfbRectangle 8


/*-----------------------------------------------------------------------------
 * Structure used to specify pixel format.
 */

typedef struct _rfbPixelFormat {

    CARD8 bitsPerPixel;		/* 8,16,32 only */

    CARD8 depth;		/* 8 to 32 */

    CARD8 bigEndian;		/* True if multi-byte pixels are interpreted
				   as big endian, or if single-bit-per-pixel
				   has most significant bit of the byte
				   corresponding to first (leftmost) pixel. Of
				   course this is meaningless for 8 bits/pix */

    CARD8 trueColour;		/* If false then we need a "colour map" to
				   convert pixels to RGB.  If true, xxxMax and
				   xxxShift specify bits used for red, green
				   and blue */

    /* the following fields are only meaningful if trueColour is true */

    CARD16 redMax;		/* maximum red value (= 2^n - 1 where n is the
				   number of bits used for red). Note this
				   value is always in big endian order. */

    CARD16 greenMax;		/* similar for green */

    CARD16 blueMax;		/* and blue */

    CARD8 redShift;		/* number of shifts needed to get the red
				   value in a pixel to the least significant
				   bit. To find the red value from a given
				   pixel, do the following:
				   1) Swap pixel value according to bigEndian
				      (e.g. if bigEndian is false and host byte
				      order is big endian, then swap).
				   2) Shift right by redShift.
				   3) AND with redMax (in host byte order).
				   4) You now have the red value between 0 and
				      redMax. */

    CARD8 greenShift;		/* similar for green */

    CARD8 blueShift;		/* and blue */

    CARD8 pad1;
    CARD16 pad2;

} rfbPixelFormat;

#define sz_rfbPixelFormat 16


/*-----------------------------------------------------------------------------
 * Structure used to describe protocol options such as tunneling methods,
 * authentication schemes and message types (protocol versions 3.7t, 3.8t).
 */

typedef struct _rfbCapabilityInfo {

    CARD32 code;		/* numeric identifier */
    CARD8 vendorSignature[4];	/* vendor identification */
    CARD8 nameSignature[8];	/* abbreviated option name */

} rfbCapabilityInfo;

#define sz_rfbCapabilityInfoVendor 4
#define sz_rfbCapabilityInfoName 8
#define sz_rfbCapabilityInfo 16

/*
 * Vendors known by TightVNC: standard VNC/RealVNC, TridiaVNC, and TightVNC.
 */

#define rfbStandardVendor "STDV"
#define rfbTridiaVncVendor "TRDV"
#define rfbTightVncVendor "TGHT"


/*****************************************************************************
 *
 * Initial handshaking messages
 *
 *****************************************************************************/

/*-----------------------------------------------------------------------------
 * Protocol Version
 *
 * The server always sends 12 bytes to start which identifies the latest RFB
 * protocol version number which it supports.  These bytes are interpreted
 * as a string of 12 ASCII characters in the format "RFB xxx.yyy\n" where
 * xxx and yyy are the major and minor version numbers (e.g. for version 3.8
 * this is "RFB 003.008\n").
 *
 * The client then replies with a similar 12-byte message giving the version
 * number of the protocol which should actually be used (which may be different
 * to that quoted by the server).
 *
 * It is intended that both clients and servers may provide some level of
 * backwards compatibility by this mechanism.  Servers in particular should
 * attempt to provide backwards compatibility, and even forwards compatibility
 * to some extent.  For example if a client demands version 3.1 of the
 * protocol, a 3.0 server can probably assume that by ignoring requests for
 * encoding types it doesn't understand, everything will still work OK.  This
 * will probably not be the case for changes in the major version number.
 *
 * The format string below can be used in sprintf or sscanf to generate or
 * decode the version string respectively.
 */

#define rfbProtocolVersionFormat "RFB %03d.%03d\n"

typedef char rfbProtocolVersionMsg[13];	/* allow extra byte for null */

#define sz_rfbProtocolVersionMsg 12


/*
 * Negotiation of the security type (protocol versions 3.7, 3.8)
 *
 * Once the protocol version has been decided, the server either sends a list
 * of supported security types, or informs the client about an error (when the
 * number of security types is 0).  Security type rfbSecTypeTight is used to
 * enable TightVNC-specific protocol extensions.  The value rfbSecTypeVncAuth
 * stands for classic VNC authentication.
 *
 * The client selects a particular security type from the list provided by the
 * server.
 */

#define rfbSecTypeInvalid 0
#define rfbSecTypeNone 1
#define rfbSecTypeVncAuth 2
#define rfbSecTypeTight 16


/*-----------------------------------------------------------------------------
 * Negotiation of Tunneling Capabilities (protocol versions 3.7t, 3.8t)
 *
 * If the chosen security type is rfbSecTypeTight, the server sends a list of
 * supported tunneling methods ("tunneling" refers to any additional layer of
 * data transformation, such as encryption or external compression.)
 *
 * nTunnelTypes specifies the number of following rfbCapabilityInfo structures
 * that list all supported tunneling methods in the order of preference.
 *
 * NOTE: If nTunnelTypes is 0, that tells the client that no tunneling can be
 * used, and the client should not send a response requesting a tunneling
 * method.
 */

typedef struct _rfbTunnelingCapsMsg {
    CARD32 nTunnelTypes;
    /* followed by nTunnelTypes * rfbCapabilityInfo structures */
} rfbTunnelingCapsMsg;

#define sz_rfbTunnelingCapsMsg 4

/*-----------------------------------------------------------------------------
 * Tunneling Method Request (protocol versions 3.7t, 3.8t)
 *
 * If the list of tunneling capabilities sent by the server was not empty, the
 * client should reply with a 32-bit code specifying a particular tunneling
 * method.  The following code should be used for no tunneling.
 */

#define rfbNoTunneling 0
#define sig_rfbNoTunneling "NOTUNNEL"


/*-----------------------------------------------------------------------------
 * Negotiation of Authentication Capabilities (protocol versions 3.7t, 3.8t)
 *
 * After setting up tunneling, the server sends a list of supported
 * authentication schemes.
 *
 * nAuthTypes specifies the number of following rfbCapabilityInfo structures
 * that list all supported authentication schemes in the order of preference.
 *
 * NOTE: If nAuthTypes is 0, that tells the client that no authentication is
 * necessary, and the client should not send a response requesting an
 * authentication scheme.
 */

typedef struct _rfbAuthenticationCapsMsg {
    CARD32 nAuthTypes;
    /* followed by nAuthTypes * rfbCapabilityInfo structures */
} rfbAuthenticationCapsMsg;

#define sz_rfbAuthenticationCapsMsg 4

/*-----------------------------------------------------------------------------
 * Authentication Scheme Request (protocol versions 3.7t, 3.8t)
 *
 * If the list of authentication capabilities sent by the server was not empty,
 * the client should reply with a 32-bit code specifying a particular
 * authentication scheme.  The following codes are supported.
 */

/* Standard authentication methods. */
#define rfbAuthNone 1
#define rfbAuthVNC 2

#define sig_rfbAuthNone "NOAUTH__"
#define sig_rfbAuthVNC "VNCAUTH_"

/* These two are not used in the mainstream version. */
#define rfbAuthUnixLogin 129
#define rfbAuthExternal 130

#define sig_rfbAuthUnixLogin "ULGNAUTH"
#define sig_rfbAuthExternal "XTRNAUTH"


/*-----------------------------------------------------------------------------
 * Authentication result codes (all protocol versions, but rfbAuthTooMany is
 * not used in protocol versions above 3.3)
 *
 * In the protocol version 3.8 and above, rfbAuthFailed is followed by a text
 * string describing the reason of failure. The text string is preceded with a
 * 32-bit counter of bytes in the string.
 */

#define rfbAuthOK 0
#define rfbAuthFailed 1
#define rfbAuthTooMany 2


/*-----------------------------------------------------------------------------
 * Client Initialisation Message
 *
 * Once the client and server are sure that they're happy to talk to one
 * another, the client sends an initialisation message.  At present this
 * message only consists of a boolean indicating whether the server should try
 * to share the desktop by leaving other clients connected, or give exclusive
 * access to this client by disconnecting all other clients.
 */

typedef struct _rfbClientInitMsg {
    CARD8 shared;
} rfbClientInitMsg;

#define sz_rfbClientInitMsg 1


/*-----------------------------------------------------------------------------
 * Server Initialisation Message
 *
 * After the client initialisation message, the server sends one of its own.
 * This tells the client the width and height of the server's framebuffer,
 * its pixel format and the name associated with the desktop.
 */

typedef struct _rfbServerInitMsg {
    CARD16 framebufferWidth;
    CARD16 framebufferHeight;
    rfbPixelFormat format;	/* the server's preferred pixel format */
    CARD32 nameLength;
    /* followed by char name[nameLength] */
} rfbServerInitMsg;

#define sz_rfbServerInitMsg (8 + sz_rfbPixelFormat)


/*-----------------------------------------------------------------------------
 * Server Interaction Capabilities Message (protocol versions 3.7t, 3.8t)
 *
 * If TightVNC protocol extensions are enabled, the server informs the client
 * what message types it supports in addition to ones defined in the standard
 * RFB protocol.
 * Also, the server sends the list of all supported encodings (note that it's
 * not necessary to advertise the "raw" encoding sinse it MUST be supported in
 * RFB 3.x protocols).
 *
 * This data immediately follows the server initialisation message.
 */

typedef struct _rfbInteractionCapsMsg {
    CARD16 nServerMessageTypes;
    CARD16 nClientMessageTypes;
    CARD16 nEncodingTypes;
    CARD16 pad;			/* reserved, must be 0 */
    /* followed by nServerMessageTypes * rfbCapabilityInfo structures */
    /* followed by nClientMessageTypes * rfbCapabilityInfo structures */
} rfbInteractionCapsMsg;

#define sz_rfbInteractionCapsMsg 8


/*
 * Following the server initialisation message it's up to the client to send
 * whichever protocol messages it wants.  Typically it will send a
 * SetPixelFormat message and a SetEncodings message, followed by a
 * FramebufferUpdateRequest.  From then on the server will send
 * FramebufferUpdate messages in response to the client's
 * FramebufferUpdateRequest messages.  The client should send
 * FramebufferUpdateRequest messages with incremental set to true when it has
 * finished processing one FramebufferUpdate and is ready to process another.
 * With a fast client, the rate at which FramebufferUpdateRequests are sent
 * should be regulated to avoid hogging the network.
 */



/*****************************************************************************
 *
 * Message types
 *
 *****************************************************************************/

/* server -> client */

#define rfbFramebufferUpdate 0
#define rfbSetColourMapEntries 1
#define rfbBell 2
#define rfbServerCutText 3

#define rfbFileListData 130
#define rfbFileDownloadData 131
#define rfbFileUploadCancel 132
#define rfbFileDownloadFailed 133

/* signatures for non-standard messages */
#define sig_rfbFileListData "FTS_LSDT"
#define sig_rfbFileDownloadData "FTS_DNDT"
#define sig_rfbFileUploadCancel "FTS_UPCN"
#define sig_rfbFileDownloadFailed "FTS_DNFL"


/* client -> server */

#define rfbSetPixelFormat 0
#define rfbFixColourMapEntries 1	/* not currently supported */
#define rfbSetEncodings 2
#define rfbFramebufferUpdateRequest 3
#define rfbKeyEvent 4
#define rfbPointerEvent 5
#define rfbClientCutText 6

#define rfbFileListRequest 130
#define rfbFileDownloadRequest 131
#define rfbFileUploadRequest 132
#define rfbFileUploadData 133
#define rfbFileDownloadCancel 134
#define rfbFileUploadFailed 135
#define rfbFileCreateDirRequest 136

/* signatures for non-standard messages */
#define sig_rfbFileListRequest "FTC_LSRQ"
#define sig_rfbFileDownloadRequest "FTC_DNRQ"
#define sig_rfbFileUploadRequest "FTC_UPRQ"
#define sig_rfbFileUploadData "FTC_UPDT"
#define sig_rfbFileDownloadCancel "FTC_DNCN"
#define sig_rfbFileUploadFailed "FTC_UPFL"
#define sig_rfbFileCreateDirRequest "FTC_FCDR"

/*****************************************************************************
 *
 * Encoding types
 *
 *****************************************************************************/

#define rfbEncodingRaw       0
#define rfbEncodingCopyRect  1
#define rfbEncodingRRE       2
#define rfbEncodingCoRRE     4
#define rfbEncodingHextile   5
#define rfbEncodingZlib      6
#define rfbEncodingTight     7
#define rfbEncodingZlibHex   8
#define rfbEncodingZRLE     16

/* signatures for basic encoding types */
#define sig_rfbEncodingRaw       "RAW_____"
#define sig_rfbEncodingCopyRect  "COPYRECT"
#define sig_rfbEncodingRRE       "RRE_____"
#define sig_rfbEncodingCoRRE     "CORRE___"
#define sig_rfbEncodingHextile   "HEXTILE_"
#define sig_rfbEncodingZlib      "ZLIB____"
#define sig_rfbEncodingTight     "TIGHT___"
#define sig_rfbEncodingZlibHex   "ZLIBHEX_"
#define sig_rfbEncodingZRLE      "ZRLE____"

/*
 * Special encoding numbers:
 *   0xFFFFFF00 .. 0xFFFFFF0F -- encoding-specific compression levels;
 *   0xFFFFFF10 .. 0xFFFFFF1F -- mouse cursor shape data;
 *   0xFFFFFF20 .. 0xFFFFFF2F -- various protocol extensions;
 *   0xFFFFFF30 .. 0xFFFFFFDF -- not allocated yet;
 *   0xFFFFFFE0 .. 0xFFFFFFEF -- quality level for JPEG compressor;
 *   0xFFFFFFF0 .. 0xFFFFFFFF -- not allocated yet.
 */

#define rfbEncodingCompressLevel0  0xFFFFFF00
#define rfbEncodingCompressLevel1  0xFFFFFF01
#define rfbEncodingCompressLevel2  0xFFFFFF02
#define rfbEncodingCompressLevel3  0xFFFFFF03
#define rfbEncodingCompressLevel4  0xFFFFFF04
#define rfbEncodingCompressLevel5  0xFFFFFF05
#define rfbEncodingCompressLevel6  0xFFFFFF06
#define rfbEncodingCompressLevel7  0xFFFFFF07
#define rfbEncodingCompressLevel8  0xFFFFFF08
#define rfbEncodingCompressLevel9  0xFFFFFF09

#define rfbEncodingXCursor         0xFFFFFF10
#define rfbEncodingRichCursor      0xFFFFFF11
#define rfbEncodingPointerPos      0xFFFFFF18

#define rfbEncodingLastRect        0xFFFFFF20
#define rfbEncodingNewFBSize       0xFFFFFF21

#define rfbEncodingQualityLevel0   0xFFFFFFE0
#define rfbEncodingQualityLevel1   0xFFFFFFE1
#define rfbEncodingQualityLevel2   0xFFFFFFE2
#define rfbEncodingQualityLevel3   0xFFFFFFE3
#define rfbEncodingQualityLevel4   0xFFFFFFE4
#define rfbEncodingQualityLevel5   0xFFFFFFE5
#define rfbEncodingQualityLevel6   0xFFFFFFE6
#define rfbEncodingQualityLevel7   0xFFFFFFE7
#define rfbEncodingQualityLevel8   0xFFFFFFE8
#define rfbEncodingQualityLevel9   0xFFFFFFE9

/* signatures for "fake" encoding types */
#define sig_rfbEncodingCompressLevel0  "COMPRLVL"
#define sig_rfbEncodingXCursor         "X11CURSR"
#define sig_rfbEncodingRichCursor      "RCHCURSR"
#define sig_rfbEncodingPointerPos      "POINTPOS"
#define sig_rfbEncodingLastRect        "LASTRECT"
#define sig_rfbEncodingNewFBSize       "NEWFBSIZ"
#define sig_rfbEncodingQualityLevel0   "JPEGQLVL"


/*****************************************************************************
 *
 * Server -> client message definitions
 *
 *****************************************************************************/


/*-----------------------------------------------------------------------------
 * FramebufferUpdate - a block of rectangles to be copied to the framebuffer.
 *
 * This message consists of a header giving the number of rectangles of pixel
 * data followed by the rectangles themselves.  The header is padded so that
 * together with the type byte it is an exact multiple of 4 bytes (to help
 * with alignment of 32-bit pixels):
 */

typedef struct _rfbFramebufferUpdateMsg {
    CARD8 type;			/* always rfbFramebufferUpdate */
    CARD8 pad;
    CARD16 nRects;
    /* followed by nRects rectangles */
} rfbFramebufferUpdateMsg;

#define sz_rfbFramebufferUpdateMsg 4

/*
 * Each rectangle of pixel data consists of a header describing the position
 * and size of the rectangle and a type word describing the encoding of the
 * pixel data, followed finally by the pixel data.  Note that if the client has
 * not sent a SetEncodings message then it will only receive raw pixel data.
 * Also note again that this structure is a multiple of 4 bytes.
 */

typedef struct _rfbFramebufferUpdateRectHeader {
    rfbRectangle r;
    CARD32 encoding;		/* one of the encoding types rfbEncoding... */
} rfbFramebufferUpdateRectHeader;

#define sz_rfbFramebufferUpdateRectHeader (sz_rfbRectangle + 4)


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * Raw Encoding.  Pixels are sent in top-to-bottom scanline order,
 * left-to-right within a scanline with no padding in between.
 */


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * CopyRect Encoding.  The pixels are specified simply by the x and y position
 * of the source rectangle.
 */

typedef struct _rfbCopyRect {
    CARD16 srcX;
    CARD16 srcY;
} rfbCopyRect;

#define sz_rfbCopyRect 4


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * RRE - Rise-and-Run-length Encoding.  We have an rfbRREHeader structure
 * giving the number of subrectangles following.  Finally the data follows in
 * the form [<bgpixel><subrect><subrect>...] where each <subrect> is
 * [<pixel><rfbRectangle>].
 */

typedef struct _rfbRREHeader {
    CARD32 nSubrects;
} rfbRREHeader;

#define sz_rfbRREHeader 4


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * CoRRE - Compact RRE Encoding.  We have an rfbRREHeader structure giving
 * the number of subrectangles following.  Finally the data follows in the form
 * [<bgpixel><subrect><subrect>...] where each <subrect> is
 * [<pixel><rfbCoRRERectangle>].  This means that
 * the whole rectangle must be at most 255x255 pixels.
 */

typedef struct _rfbCoRRERectangle {
    CARD8 x;
    CARD8 y;
    CARD8 w;
    CARD8 h;
} rfbCoRRERectangle;

#define sz_rfbCoRRERectangle 4


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * Hextile Encoding.  The rectangle is divided up into "tiles" of 16x16 pixels,
 * starting at the top left going in left-to-right, top-to-bottom order.  If
 * the width of the rectangle is not an exact multiple of 16 then the width of
 * the last tile in each row will be correspondingly smaller.  Similarly if the
 * height is not an exact multiple of 16 then the height of each tile in the
 * final row will also be smaller.  Each tile begins with a "subencoding" type
 * byte, which is a mask made up of a number of bits.  If the Raw bit is set
 * then the other bits are irrelevant; w*h pixel values follow (where w and h
 * are the width and height of the tile).  Otherwise the tile is encoded in a
 * similar way to RRE, except that the position and size of each subrectangle
 * can be specified in just two bytes.  The other bits in the mask are as
 * follows:
 *
 * BackgroundSpecified - if set, a pixel value follows which specifies
 *    the background colour for this tile.  The first non-raw tile in a
 *    rectangle must have this bit set.  If this bit isn't set then the
 *    background is the same as the last tile.
 *
 * ForegroundSpecified - if set, a pixel value follows which specifies
 *    the foreground colour to be used for all subrectangles in this tile.
 *    If this bit is set then the SubrectsColoured bit must be zero.
 *
 * AnySubrects - if set, a single byte follows giving the number of
 *    subrectangles following.  If not set, there are no subrectangles (i.e.
 *    the whole tile is just solid background colour).
 *
 * SubrectsColoured - if set then each subrectangle is preceded by a pixel
 *    value giving the colour of that subrectangle.  If not set, all
 *    subrectangles are the same colour, the foreground colour;  if the
 *    ForegroundSpecified bit wasn't set then the foreground is the same as
 *    the last tile.
 *
 * The position and size of each subrectangle is specified in two bytes.  The
 * Pack macros below can be used to generate the two bytes from x, y, w, h,
 * and the Extract macros can be used to extract the x, y, w, h values from
 * the two bytes.
 */

#define rfbHextileRaw			(1 << 0)
#define rfbHextileBackgroundSpecified	(1 << 1)
#define rfbHextileForegroundSpecified	(1 << 2)
#define rfbHextileAnySubrects		(1 << 3)
#define rfbHextileSubrectsColoured	(1 << 4)

#define rfbHextilePackXY(x,y) (((x) << 4) | (y))
#define rfbHextilePackWH(w,h) ((((w)-1) << 4) | ((h)-1))
#define rfbHextileExtractX(byte) ((byte) >> 4)
#define rfbHextileExtractY(byte) ((byte) & 0xf)
#define rfbHextileExtractW(byte) (((byte) >> 4) + 1)
#define rfbHextileExtractH(byte) (((byte) & 0xf) + 1)

/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * ZLIB - zlib compression Encoding.  We have an rfbZlibHeader structure
 * giving the number of bytes to follow.  Finally the data follows in
 * zlib compressed format.
 */

typedef struct _rfbZlibHeader {
    CARD32 nBytes;
} rfbZlibHeader;

#define sz_rfbZlibHeader 4


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * Tight Encoding.
 *
 *-- The first byte of each Tight-encoded rectangle is a "compression control
 *   byte". Its format is as follows (bit 0 is the least significant one):
 *
 *   bit 0:    if 1, then compression stream 0 should be reset;
 *   bit 1:    if 1, then compression stream 1 should be reset;
 *   bit 2:    if 1, then compression stream 2 should be reset;
 *   bit 3:    if 1, then compression stream 3 should be reset;
 *   bits 7-4: if 1000 (0x08), then the compression type is "fill",
 *             if 1001 (0x09), then the compression type is "jpeg",
 *             if 0xxx, then the compression type is "basic",
 *             values greater than 1001 are not valid.
 *
 * If the compression type is "basic", then bits 6..4 of the
 * compression control byte (those xxx in 0xxx) specify the following:
 *
 *   bits 5-4:  decimal representation is the index of a particular zlib
 *              stream which should be used for decompressing the data;
 *   bit 6:     if 1, then a "filter id" byte is following this byte.
 *
 *-- The data that follows after the compression control byte described
 * above depends on the compression type ("fill", "jpeg" or "basic").
 *
 *-- If the compression type is "fill", then the only pixel value follows, in
 * client pixel format (see NOTE 1). This value applies to all pixels of the
 * rectangle.
 *
 *-- If the compression type is "jpeg", the following data stream looks like
 * this:
 *
 *   1..3 bytes:  data size (N) in compact representation;
 *   N bytes:     JPEG image.
 *
 * Data size is compactly represented in one, two or three bytes, according
 * to the following scheme:
 *
 *  0xxxxxxx                    (for values 0..127)
 *  1xxxxxxx 0yyyyyyy           (for values 128..16383)
 *  1xxxxxxx 1yyyyyyy zzzzzzzz  (for values 16384..4194303)
 *
 * Here each character denotes one bit, xxxxxxx are the least significant 7
 * bits of the value (bits 0-6), yyyyyyy are bits 7-13, and zzzzzzzz are the
 * most significant 8 bits (bits 14-21). For example, decimal value 10000
 * should be represented as two bytes: binary 10010000 01001110, or
 * hexadecimal 90 4E.
 *
 *-- If the compression type is "basic" and bit 6 of the compression control
 * byte was set to 1, then the next (second) byte specifies "filter id" which
 * tells the decoder what filter type was used by the encoder to pre-process
 * pixel data before the compression. The "filter id" byte can be one of the
 * following:
 *
 *   0:  no filter ("copy" filter);
 *   1:  "palette" filter;
 *   2:  "gradient" filter.
 *
 *-- If bit 6 of the compression control byte is set to 0 (no "filter id"
 * byte), or if the filter id is 0, then raw pixel values in the client
 * format (see NOTE 1) will be compressed. See below details on the
 * compression.
 *
 *-- The "gradient" filter pre-processes pixel data with a simple algorithm
 * which converts each color component to a difference between a "predicted"
 * intensity and the actual intensity. Such a technique does not affect
 * uncompressed data size, but helps to compress photo-like images better. 
 * Pseudo-code for converting intensities to differences is the following:
 *
 *   P[i,j] := V[i-1,j] + V[i,j-1] - V[i-1,j-1];
 *   if (P[i,j] < 0) then P[i,j] := 0;
 *   if (P[i,j] > MAX) then P[i,j] := MAX;
 *   D[i,j] := V[i,j] - P[i,j];
 *
 * Here V[i,j] is the intensity of a color component for a pixel at
 * coordinates (i,j). MAX is the maximum value of intensity for a color
 * component.
 *
 *-- The "palette" filter converts true-color pixel data to indexed colors
 * and a palette which can consist of 2..256 colors. If the number of colors
 * is 2, then each pixel is encoded in 1 bit, otherwise 8 bits is used to
 * encode one pixel. 1-bit encoding is performed such way that the most
 * significant bits correspond to the leftmost pixels, and each raw of pixels
 * is aligned to the byte boundary. When "palette" filter is used, the
 * palette is sent before the pixel data. The palette begins with an unsigned
 * byte which value is the number of colors in the palette minus 1 (i.e. 1
 * means 2 colors, 255 means 256 colors in the palette). Then follows the
 * palette itself which consist of pixel values in client pixel format (see
 * NOTE 1).
 *
 *-- The pixel data is compressed using the zlib library. But if the data
 * size after applying the filter but before the compression is less then 12,
 * then the data is sent as is, uncompressed. Four separate zlib streams
 * (0..3) can be used and the decoder should read the actual stream id from
 * the compression control byte (see NOTE 2).
 *
 * If the compression is not used, then the pixel data is sent as is,
 * otherwise the data stream looks like this:
 *
 *   1..3 bytes:  data size (N) in compact representation;
 *   N bytes:     zlib-compressed data.
 *
 * Data size is compactly represented in one, two or three bytes, just like
 * in the "jpeg" compression method (see above).
 *
 *-- NOTE 1. If the color depth is 24, and all three color components are
 * 8-bit wide, then one pixel in Tight encoding is always represented by
 * three bytes, where the first byte is red component, the second byte is
 * green component, and the third byte is blue component of the pixel color
 * value. This applies to colors in palettes as well.
 *
 *-- NOTE 2. The decoder must reset compression streams' states before
 * decoding the rectangle, if some of bits 0,1,2,3 in the compression control
 * byte are set to 1. Note that the decoder must reset zlib streams even if
 * the compression type is "fill" or "jpeg".
 *
 *-- NOTE 3. The "gradient" filter and "jpeg" compression may be used only
 * when bits-per-pixel value is either 16 or 32, not 8.
 *
 *-- NOTE 4. The width of any Tight-encoded rectangle cannot exceed 2048
 * pixels. If a rectangle is wider, it must be split into several rectangles
 * and each one should be encoded separately.
 *
 */

#define rfbTightExplicitFilter         0x04
#define rfbTightFill                   0x08
#define rfbTightJpeg                   0x09
#define rfbTightMaxSubencoding         0x09

/* Filters to improve compression efficiency */
#define rfbTightFilterCopy             0x00
#define rfbTightFilterPalette          0x01
#define rfbTightFilterGradient         0x02


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * ZLIBHEX - zlib compressed Hextile Encoding.  Essentially, this is the
 * hextile encoding with zlib compression on the tiles that can not be
 * efficiently encoded with one of the other hextile subencodings.  The
 * new zlib subencoding uses two bytes to specify the length of the
 * compressed tile and then the compressed data follows.  As with the
 * raw sub-encoding, the zlib subencoding invalidates the other
 * values, if they are also set.
 */

#define rfbHextileZlibRaw		(1 << 5)
#define rfbHextileZlibHex		(1 << 6)


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * XCursor encoding. This is a special encoding used to transmit X-style
 * cursor shapes from server to clients. Note that for this encoding,
 * coordinates in rfbFramebufferUpdateRectHeader structure hold hotspot
 * position (r.x, r.y) and cursor size (r.w, r.h). If (w * h != 0), two RGB
 * samples are sent after header in the rfbXCursorColors structure. They
 * denote foreground and background colors of the cursor. If a client
 * supports only black-and-white cursors, it should ignore these colors and
 * assume that foreground is black and background is white. Next, two bitmaps
 * (1 bits per pixel) follow: first one with actual data (value 0 denotes
 * background color, value 1 denotes foreground color), second one with
 * transparency data (bits with zero value mean that these pixels are
 * transparent). Both bitmaps represent cursor data in a byte stream, from
 * left to right, from top to bottom, and each row is byte-aligned. Most
 * significant bits correspond to leftmost pixels. The number of bytes in
 * each row can be calculated as ((w + 7) / 8). If (w * h == 0), cursor
 * should be hidden (or default local cursor should be set by the client).
 */

typedef struct _rfbXCursorColors {
    CARD8 foreRed;
    CARD8 foreGreen;
    CARD8 foreBlue;
    CARD8 backRed;
    CARD8 backGreen;
    CARD8 backBlue;
} rfbXCursorColors;

#define sz_rfbXCursorColors 6


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * RichCursor encoding. This is a special encoding used to transmit cursor
 * shapes from server to clients. It is similar to the XCursor encoding but
 * uses client pixel format instead of two RGB colors to represent cursor
 * image. For this encoding, coordinates in rfbFramebufferUpdateRectHeader
 * structure hold hotspot position (r.x, r.y) and cursor size (r.w, r.h).
 * After header, two pixmaps follow: first one with cursor image in current
 * client pixel format (like in raw encoding), second with transparency data
 * (1 bit per pixel, exactly the same format as used for transparency bitmap
 * in the XCursor encoding). If (w * h == 0), cursor should be hidden (or
 * default local cursor should be set by the client).
 */


/*-----------------------------------------------------------------------------
 * SetColourMapEntries - these messages are only sent if the pixel
 * format uses a "colour map" (i.e. trueColour false) and the client has not
 * fixed the entire colour map using FixColourMapEntries.  In addition they
 * will only start being sent after the client has sent its first
 * FramebufferUpdateRequest.  So if the client always tells the server to use
 * trueColour then it never needs to process this type of message.
 */

typedef struct _rfbSetColourMapEntriesMsg {
    CARD8 type;			/* always rfbSetColourMapEntries */
    CARD8 pad;
    CARD16 firstColour;
    CARD16 nColours;

    /* Followed by nColours * 3 * CARD16
       r1, g1, b1, r2, g2, b2, r3, g3, b3, ..., rn, bn, gn */

} rfbSetColourMapEntriesMsg;

#define sz_rfbSetColourMapEntriesMsg 6



/*-----------------------------------------------------------------------------
 * Bell - ring a bell on the client if it has one.
 */

typedef struct _rfbBellMsg {
    CARD8 type;			/* always rfbBell */
} rfbBellMsg;

#define sz_rfbBellMsg 1



/*-----------------------------------------------------------------------------
 * ServerCutText - the server has new text in its cut buffer.
 */

typedef struct _rfbServerCutTextMsg {
    CARD8 type;			/* always rfbServerCutText */
    CARD8 pad1;
    CARD16 pad2;
    CARD32 length;
    /* followed by char text[length] */
} rfbServerCutTextMsg;

#define sz_rfbServerCutTextMsg 8

/*-----------------------------------------------------------------------------
 * FileListData
 */

typedef struct _rfbFileListDataMsg {
    CARD8 type;
    CARD8 flags;
    CARD16 numFiles;
    CARD16 dataSize;
    CARD16 compressedSize;
    /* Followed by SizeData[numFiles] */
    /* Followed by Filenames[compressedSize] */
} rfbFileListDataMsg;

#define sz_rfbFileListDataMsg 8

/*-----------------------------------------------------------------------------
 * FileDownloadData
 */

typedef struct _rfbFileDownloadDataMsg {
    CARD8 type;
    CARD8 compressLevel;
    CARD16 realSize;
    CARD16 compressedSize;
    /* Followed by File[copressedSize], 
       but if (realSize = compressedSize = 0) followed by CARD32 modTime  */
} rfbFileDownloadDataMsg;

#define sz_rfbFileDownloadDataMsg 6


/*-----------------------------------------------------------------------------
 * FileUploadCancel
 */

typedef struct _rfbFileUploadCancelMsg {
    CARD8 type;
    CARD8 unused;
    CARD16 reasonLen;
    /* Followed by reason[reasonLen] */
} rfbFileUploadCancelMsg;

#define sz_rfbFileUploadCancelMsg 4

/*-----------------------------------------------------------------------------
 * FileDownloadFailed
 */

typedef struct _rfbFileDownloadFailedMsg {
    CARD8 type;
    CARD8 unused;
    CARD16 reasonLen;
    /* Followed by reason[reasonLen] */
} rfbFileDownloadFailedMsg;

#define sz_rfbFileDownloadFailedMsg 4

/*-----------------------------------------------------------------------------
 * Union of all server->client messages.
 */

typedef union _rfbServerToClientMsg {
    CARD8 type;
    rfbFramebufferUpdateMsg fu;
    rfbSetColourMapEntriesMsg scme;
    rfbBellMsg b;
    rfbServerCutTextMsg sct;
    rfbFileListDataMsg fld;
    rfbFileDownloadDataMsg fdd;
    rfbFileUploadCancelMsg fuc;
    rfbFileDownloadFailedMsg fdf;
} rfbServerToClientMsg;



/*****************************************************************************
 *
 * Message definitions (client -> server)
 *
 *****************************************************************************/


/*-----------------------------------------------------------------------------
 * SetPixelFormat - tell the RFB server the format in which the client wants
 * pixels sent.
 */

typedef struct _rfbSetPixelFormatMsg {
    CARD8 type;			/* always rfbSetPixelFormat */
    CARD8 pad1;
    CARD16 pad2;
    rfbPixelFormat format;
} rfbSetPixelFormatMsg;

#define sz_rfbSetPixelFormatMsg (sz_rfbPixelFormat + 4)


/*-----------------------------------------------------------------------------
 * FixColourMapEntries - when the pixel format uses a "colour map", fix
 * read-only colour map entries.
 *
 *    ***************** NOT CURRENTLY SUPPORTED *****************
 */

typedef struct _rfbFixColourMapEntriesMsg {
    CARD8 type;			/* always rfbFixColourMapEntries */
    CARD8 pad;
    CARD16 firstColour;
    CARD16 nColours;

    /* Followed by nColours * 3 * CARD16
       r1, g1, b1, r2, g2, b2, r3, g3, b3, ..., rn, bn, gn */

} rfbFixColourMapEntriesMsg;

#define sz_rfbFixColourMapEntriesMsg 6


/*-----------------------------------------------------------------------------
 * SetEncodings - tell the RFB server which encoding types we accept.  Put them
 * in order of preference, if we have any.  We may always receive raw
 * encoding, even if we don't specify it here.
 */

typedef struct _rfbSetEncodingsMsg {
    CARD8 type;			/* always rfbSetEncodings */
    CARD8 pad;
    CARD16 nEncodings;
    /* followed by nEncodings * CARD32 encoding types */
} rfbSetEncodingsMsg;

#define sz_rfbSetEncodingsMsg 4


/*-----------------------------------------------------------------------------
 * FramebufferUpdateRequest - request for a framebuffer update.  If incremental
 * is true then the client just wants the changes since the last update.  If
 * false then it wants the whole of the specified rectangle.
 */

typedef struct _rfbFramebufferUpdateRequestMsg {
    CARD8 type;			/* always rfbFramebufferUpdateRequest */
    CARD8 incremental;
    CARD16 x;
    CARD16 y;
    CARD16 w;
    CARD16 h;
} rfbFramebufferUpdateRequestMsg;

#define sz_rfbFramebufferUpdateRequestMsg 10


/*-----------------------------------------------------------------------------
 * KeyEvent - key press or release
 *
 * Keys are specified using the "keysym" values defined by the X Window System.
 * For most ordinary keys, the keysym is the same as the corresponding ASCII
 * value.  Other common keys are:
 *
 * BackSpace		0xff08
 * Tab			0xff09
 * Return or Enter	0xff0d
 * Escape		0xff1b
 * Insert		0xff63
 * Delete		0xffff
 * Home			0xff50
 * End			0xff57
 * Page Up		0xff55
 * Page Down		0xff56
 * Left			0xff51
 * Up			0xff52
 * Right		0xff53
 * Down			0xff54
 * F1			0xffbe
 * F2			0xffbf
 * ...			...
 * F12			0xffc9
 * Shift		0xffe1
 * Control		0xffe3
 * Meta			0xffe7
 * Alt			0xffe9
 */

typedef struct _rfbKeyEventMsg {
    CARD8 type;			/* always rfbKeyEvent */
    CARD8 down;			/* true if down (press), false if up */
    CARD16 pad;
    CARD32 key;			/* key is specified as an X keysym */
} rfbKeyEventMsg;

#define sz_rfbKeyEventMsg 8


/*-----------------------------------------------------------------------------
 * PointerEvent - mouse/pen move and/or button press.
 */

typedef struct _rfbPointerEventMsg {
    CARD8 type;			/* always rfbPointerEvent */
    CARD8 buttonMask;		/* bits 0-7 are buttons 1-8, 0=up, 1=down */
    CARD16 x;
    CARD16 y;
} rfbPointerEventMsg;

#define rfbButton1Mask 1
#define rfbButton2Mask 2
#define rfbButton3Mask 4
#define rfbButton4Mask 8
#define rfbButton5Mask 16

#define sz_rfbPointerEventMsg 6



/*-----------------------------------------------------------------------------
 * ClientCutText - the client has new text in its cut buffer.
 */

typedef struct _rfbClientCutTextMsg {
    CARD8 type;			/* always rfbClientCutText */
    CARD8 pad1;
    CARD16 pad2;
    CARD32 length;
    /* followed by char text[length] */
} rfbClientCutTextMsg;

#define sz_rfbClientCutTextMsg 8

/*-----------------------------------------------------------------------------
 * FileListRequest
 */

typedef struct _rfbFileListRequestMsg {
    CARD8 type;
    CARD8 flags;
    CARD16 dirNameSize;
    /* Followed by char Dirname[dirNameSize] */
} rfbFileListRequestMsg;

#define sz_rfbFileListRequestMsg 4

/*-----------------------------------------------------------------------------
 * FileDownloadRequest
 */

typedef struct _rfbFileDownloadRequestMsg {
    CARD8 type;
    CARD8 compressedLevel;
    CARD16 fNameSize;
    CARD32 position;
    /* Followed by char Filename[fNameSize] */
} rfbFileDownloadRequestMsg;

#define sz_rfbFileDownloadRequestMsg 8

/*-----------------------------------------------------------------------------
 * FileUploadRequest
 */

typedef struct _rfbFileUploadRequestMsg {
    CARD8 type;
    CARD8 compressedLevel;
    CARD16 fNameSize;
    CARD32 position;
    /* Followed by char Filename[fNameSize] */
} rfbFileUploadRequestMsg;

#define sz_rfbFileUploadRequestMsg 8


/*-----------------------------------------------------------------------------
 * FileUploadData
 */

typedef struct _rfbFileUploadDataMsg {
    CARD8 type;
    CARD8 compressedLevel;
    CARD16 realSize;
    CARD16 compressedSize;
    /* Followed by File[compressedSize], 
       but if (realSize = compressedSize = 0) followed by CARD32 modTime  */
} rfbFileUploadDataMsg;

#define sz_rfbFileUploadDataMsg 6

/*-----------------------------------------------------------------------------
 * FileDownloadCancel
 */

typedef struct _rfbFileDownloadCancelMsg {
    CARD8 type;
    CARD8 unused;
    CARD16 reasonLen;
    /* Followed by reason[reasonLen] */
} rfbFileDownloadCancelMsg;

#define sz_rfbFileDownloadCancelMsg 4

/*-----------------------------------------------------------------------------
 * FileUploadFailed
 */

typedef struct _rfbFileUploadFailedMsg {
    CARD8 type;
    CARD8 unused;
    CARD16 reasonLen;
    /* Followed by reason[reasonLen] */
} rfbFileUploadFailedMsg;

#define sz_rfbFileUploadFailedMsg 4

/*-----------------------------------------------------------------------------
 * FileCreateDirRequest
 */

typedef struct _rfbFileCreateDirRequestMsg {
    CARD8 type;
    CARD8 unused;
    CARD16 dNameLen;
    /* Followed by dName[dNameLen] */
} rfbFileCreateDirRequestMsg;

#define sz_rfbFileCreateDirRequestMsg 4

/*-----------------------------------------------------------------------------
 * Union of all client->server messages.
 */

typedef union _rfbClientToServerMsg {
    CARD8 type;
    rfbSetPixelFormatMsg spf;
    rfbFixColourMapEntriesMsg fcme;
    rfbSetEncodingsMsg se;
    rfbFramebufferUpdateRequestMsg fur;
    rfbKeyEventMsg ke;
    rfbPointerEventMsg pe;
    rfbClientCutTextMsg cct;
    rfbFileListRequestMsg flr;
    rfbFileDownloadRequestMsg fdr;
    rfbFileUploadRequestMsg fupr;
    rfbFileUploadDataMsg fud;
    rfbFileDownloadCancelMsg fdc;
    rfbFileUploadFailedMsg fuf;
    rfbFileCreateDirRequestMsg fcdr;
} rfbClientToServerMsg;
