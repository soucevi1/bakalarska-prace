package com.bp.dirtycow;

import android.util.Log;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

/*
Zdroj: https://stackoverflow.com/q/22018305/6136143
 */

public class CClient implements Runnable {
    private Socket socket;
    private String message;
    private String ServerIP;
    private int ServerPort;

    public CClient(String ip, int port, String msg){

        this.ServerIP = ip;
        this.message = msg;
        this.ServerPort = port;
    }

    public void run()
    {
        try
        {
            socket = new Socket(ServerIP, ServerPort);

        }
        catch(Exception e)
        {
            Log.e("APLIKACE", "Socket creation error:" + e.toString());
            return;
        }

        Send(message);
    }

    public void Send(String s)
    {
        try
        {
            PrintWriter outToServer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            outToServer.print(s + "\n");
            outToServer.flush();
            outToServer.close();
        }
        catch (UnknownHostException e) {
            Log.e("APLIKACE", e.toString());
        } catch (IOException e) {
            Log.e("APLIKACE", e.toString());
        }catch (Exception e) {
            Log.e("APLIKACE", e.toString());
        }

    }
}