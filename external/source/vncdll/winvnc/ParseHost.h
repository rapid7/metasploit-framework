//  Copyright (C) 2006 Constantin Kaplinsky. All Rights Reserved.
//
//  TightVNC is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// TightVNC distribution homepage on the Web: http://www.tightvnc.com/

//
// The ParseHostPort function parses a VNC host name which can be specified
// in one of these formats:
//   (1) hostname
//   (2) hostname:display   (display < 100)
//   (3) hostname:port      (port >= 100)
//   (4) hostname::port
// The function determines and returns the port number, and modifies str[]
// by inserting a zero byte in place of the first colon found in the string.
// The algorithm of determining the port number is as follows:
//   (1) if there are no colons in the string, base_port is used;
//   (2) if there is one colon and the following number is less than 100,
//       then the port number is calculated by adding this number (display
//       number) to base_port;
//   (3) if there is one colon and the following number is 100 or greater,
//       then this number is interpreted as a port number;
//   (4) if there are two colons, the following number is always treated as
//       a port number.
//

int ParseHostPort(char *str, int base_port);
