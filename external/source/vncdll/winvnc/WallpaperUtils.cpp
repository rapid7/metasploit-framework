//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
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
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.

#include "WallpaperUtils.h"

WallpaperUtils::WallpaperUtils()
{
	m_restore_ActiveDesktop = false;
	m_restore_wallpaper = false;
}

void
WallpaperUtils::KillActiveDesktop()
{
  // Contact Active Desktop if possible
  HRESULT result;
  IActiveDesktop* active_desktop = 0;
  result = CoCreateInstance(CLSID_ActiveDesktop, NULL, CLSCTX_INPROC_SERVER,
    IID_IActiveDesktop, (void**)&active_desktop);
  if (result != S_OK) {
    return;
  }

  // Get Active Desktop options
  COMPONENTSOPT options;
  options.dwSize = sizeof(options);
  result = active_desktop->GetDesktopItemOptions(&options, 0);
  if (result != S_OK) {
    active_desktop->Release();
    return;
  }

  // Disable if currently active
  m_restore_ActiveDesktop = (options.fActiveDesktop != 0);
  if (options.fActiveDesktop) {
    options.fActiveDesktop = FALSE;
    result = active_desktop->SetDesktopItemOptions(&options, 0);
    if (result != S_OK) {
      active_desktop->Release();
      return;
    }
  }
  active_desktop->ApplyChanges(AD_APPLY_REFRESH);
  active_desktop->Release();
}

void
WallpaperUtils::KillWallpaper()
{
	if (!m_restore_wallpaper) {
		// Tell all applications that there is no wallpaper
		// Note that this doesn't change the wallpaper registry setting!
		SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, "", SPIF_SENDCHANGE);
		m_restore_wallpaper = true;
	}

	CoInitialize(NULL);
	KillActiveDesktop();
	CoUninitialize();
}

void
WallpaperUtils::RestoreActiveDesktop()
{
  // Contact Active Desktop if possible
  HRESULT result;
  IActiveDesktop* active_desktop = 0;
  result = CoCreateInstance(CLSID_ActiveDesktop, NULL, CLSCTX_INPROC_SERVER,
    IID_IActiveDesktop, (void**)&active_desktop);
  if (result != S_OK) {
    return;
  }

  // Get Active Desktop options
  COMPONENTSOPT options;
  options.dwSize = sizeof(options);
  result = active_desktop->GetDesktopItemOptions(&options, 0);
  if (result != S_OK) {
    active_desktop->Release();
    return;
  }

  // Re-enable if previously disabled
  if (m_restore_ActiveDesktop) {
    m_restore_ActiveDesktop = false;
    options.fActiveDesktop = TRUE;
    result = active_desktop->SetDesktopItemOptions(&options, 0);
    if (result != S_OK) {
      active_desktop->Release();
      return;
    }
  }

  active_desktop->ApplyChanges(AD_APPLY_REFRESH);
  active_desktop->Release();
}

void
WallpaperUtils::RestoreWallpaper()
{
	CoInitialize(NULL);
	RestoreActiveDesktop();
	CoUninitialize();

	if (m_restore_wallpaper) {
		SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, NULL, SPIF_SENDCHANGE);
		m_restore_wallpaper = false;
	}
}

