# -*- coding: binary -*-
# CorrM @ fb.me/IslamNofl

module Rex
module Post
module Meterpreter
module Extensions
module AppApi

##
#
# Apps
#
##

TLV_TYPE_APPS_LIST          = TLV_META_TYPE_STRING   | (TLV_EXTENSIONS + 2911)
TLV_TYPE_APPS_LIST_OPT      = TLV_META_TYPE_UINT     | (TLV_EXTENSIONS + 2912)

TLV_TYPE_APP_PACKAGE_NAME   = TLV_META_TYPE_STRING   | (TLV_EXTENSIONS + 2913);
TLV_TYPE_APP_APK_PATH       = TLV_META_TYPE_STRING   | (TLV_EXTENSIONS + 2914);
TLV_TYPE_APP_INSTALL_ENUM   = TLV_META_TYPE_UINT     | (TLV_EXTENSIONS + 2915);

TLV_TYPE_APP_RUN_ENUM       = TLV_META_TYPE_UINT     | (TLV_EXTENSIONS + 2916);


end; end; end; end; end

