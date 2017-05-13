package io.mgold.seclabvoip;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.media.MediaPlayer;
import android.media.MediaRecorder;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Objects;
import java.util.Random;
import java.util.Scanner;

public class MainActivity extends AppCompatActivity {

    TextView logText;
    Button call, add;
    EditText ipText, userText, keyText;
    Spinner callUser;
    ScrollView scroll;
    String log = "";
    ServerSocket serverSocket;
    String privKey;
    String pubKey;
    PublicKey pub;
    PrivateKey pri;

    HashMap<String, String> keys = new HashMap<>();
    HashMap<String, String> users = new HashMap<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        logText = (TextView) findViewById(R.id.msg);
        call = (Button) findViewById(R.id.callbutton);
        add = (Button) findViewById(R.id.contactbutton);
        ipText = (EditText) findViewById(R.id.callip);
        userText = (EditText) findViewById(R.id.contactuser);
        keyText = (EditText) findViewById(R.id.contactkey);
        callUser = (Spinner) findViewById(R.id.calluser);
        scroll = (ScrollView) findViewById(R.id.scroll);

        log = getIpAddress();
        logText.setText(log);
        scroll.fullScroll(View.FOCUS_DOWN);

        try {
            File file = new File(getApplicationContext().getFilesDir(), "id_rsa");
            FileInputStream fis = new FileInputStream(file);
            Scanner s = new Scanner(fis).useDelimiter("\\Z");
            privKey = s.next();
            fis.close();
            file = new File(getApplicationContext().getFilesDir(), "id_rsa.pub");
            fis = new FileInputStream(file);
            s = new Scanner(fis).useDelimiter("\\Z");
            pubKey = s.next();
            fis.close();
            pub = decodePublicKey(pubKey);
            pri = decodePrivateKey(privKey);
        } catch (Exception e) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                KeyPair kp = kpg.generateKeyPair();
                KeyFactory fact = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec pubSpec = fact.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
                PKCS8EncodedKeySpec privSpec = fact.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
                pub = kp.getPublic();
                pri = kp.getPrivate();

                privKey = new String(Base64.encode(privSpec.getEncoded(), Base64.NO_WRAP));
                pubKey = new String(Base64.encode(pubSpec.getEncoded(), Base64.NO_WRAP));
                File file = new File(getApplicationContext().getFilesDir(), "id_rsa");
                file.createNewFile();
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(privKey.getBytes());
                fos.close();
                file = new File(getApplicationContext().getFilesDir(), "id_rsa.pub");
                file.createNewFile();
                fos = new FileOutputStream(file);
                fos.write(pubKey.getBytes());
                fos.close();

            } catch (Exception e1) {
                e1.printStackTrace();
                log += "Error: " + e.toString() + "\n";
                MainActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        logText.setText(log);
                        scroll.fullScroll(View.FOCUS_DOWN);
                    }
                });
                return;
            }
        }

        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(null, pubKey);
        clipboard.setPrimaryClip(clip);
        log += "Public key copied to clipboard.\n";

        loadContacts();

        log += "Contacts loaded from storage.\n";

        MainActivity.this.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                logText.setText(log);
                scroll.fullScroll(View.FOCUS_DOWN);
            }
        });

        call.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                doCall();
            }
        });

        add.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                addContact();
                log += "Contact Added.\n";
                MainActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        logText.setText(log);
                        scroll.fullScroll(View.FOCUS_DOWN);
                    }
                });
            }
        });

        Thread socketServerThread = new Thread(new SocketServerThread());
        socketServerThread.start();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try {
            if (serverSocket != null)
                serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private class SocketServerThread extends Thread {

        static final int SocketServerPORT = 8080;

        @Override
        public void run() {
            try {
                serverSocket = new ServerSocket(SocketServerPORT);

                while (true) {
                    Socket socket = serverSocket.accept();
                    log += "Received call from " + socket.getInetAddress() + "\n";

                    MainActivity.this.runOnUiThread(new Runnable() {

                        @Override
                        public void run() {
                            logText.setText(log);
                            scroll.fullScroll(View.FOCUS_DOWN);
                        }
                    });

                    SocketServerReplyThread socketServerReplyThread = new SocketServerReplyThread(
                            socket);
                    socketServerReplyThread.run();

                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private class SocketServerReplyThread extends Thread {

        private Socket hostThreadSocket;

        SocketServerReplyThread(Socket socket) {
            hostThreadSocket = socket;
        }

        @Override
        public void run() {
            OutputStream outputStream;
            InputStream inputStream;

            try {
                outputStream = hostThreadSocket.getOutputStream();
                inputStream = hostThreadSocket.getInputStream();

                if (performHandshake(inputStream, outputStream))
                    log += "Accepted call from a contact.\n";
                else
                    log += "Call was rejected for one or more reasons.\n";

                MainActivity.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        logText.setText(log);
                        scroll.fullScroll(View.FOCUS_DOWN);
                    }
                });

                TalkThread tt = new TalkThread(hostThreadSocket);
                tt.run();

                inputStream.close();
                outputStream.close();

                MainActivity.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        logText.setText(log);
                        scroll.fullScroll(View.FOCUS_DOWN);
                    }
                });

            } catch (Exception e) {
                e.printStackTrace();
                log += "Error: " + e.toString() + "\n";
            }

            MainActivity.this.runOnUiThread(new Runnable() {

                @Override
                public void run() {
                    logText.setText(log);
                    scroll.fullScroll(View.FOCUS_DOWN);
                }
            });
        }
    }

    private class CallThread extends Thread {
        String ip;

        CallThread(String ip) {
            this.ip = ip;
        }

        @Override
        public void run() {
            try {
                Socket sock = new Socket(ip, 8080);
                InputStream is = sock.getInputStream();
                OutputStream os = sock.getOutputStream();
                Scanner s = new Scanner(is).useDelimiter("\n");
                PrintStream ps = new PrintStream(os);
                Random rand = new SecureRandom();
                Signature sig = Signature.getInstance("SHA256withRSA");
                pub = decodePublicKey(users.get(callUser.getSelectedItem().toString()));
                // Step 1: Send public key
                ps.println(pubKey);
                // Step 2: Receive generated token
                String token = s.next();
                // Step 3: Sign token and send back
                sig.initSign(pri);
                sig.update(new BigInteger(token, 16).toByteArray());
                String signed = new String(sig.sign());
                ps.println(signed);
                // Step 4: Check if we received an ACK
                String ack = s.next();
                if (!ack.equals("ACK"))
                    throw new Exception("Did not receive ACK");
                // Step 5: Generate a token and send to the server
                byte[] buf = new byte[8];
                rand.nextBytes(buf);
                for (int i = 0; i < 8; i++) {
                    ps.printf("%02x", buf[i]);
                }
                ps.println();
                // Step 6: Receive signed token from server, send ACK/NAK
                signed = s.next();
                sig.initVerify(pub);
                sig.update(buf);
                if (sig.verify(signed.getBytes())) {
                    ps.println("ACK");
                } else {
                    ps.println("NAK");
                }

                TalkThread tt = new TalkThread(sock);
                tt.run();

                is.close();
                os.close();
                sock.close();
            } catch (Exception e) {
                log += "Call could not be connected because an error occured.\n";
                log += e.toString();
                e.printStackTrace();
            }
            MainActivity.this.runOnUiThread(new Runnable() {

                @Override
                public void run() {
                    logText.setText(log);
                    scroll.fullScroll(View.FOCUS_DOWN);
                }
            });
        }
    }

    private boolean performHandshake(InputStream is, OutputStream os) throws Exception {
        Scanner s = new Scanner(is).useDelimiter("\n");
        PrintStream ps = new PrintStream(os);
        Random rand = new SecureRandom();
        Signature sig = Signature.getInstance("SHA256withRSA");
        // Step 1: Receive public key from client and check if we have as contact
        pub = decodePublicKey(s.next());
        if (!keys.containsKey(pub))
            return false;
        // Step 2: Generate a token and send to the client
        byte[] buf = new byte[8];
        rand.nextBytes(buf);
        for (int i = 0; i < 8; i++) {
            ps.printf("%02x", buf[i]);
        }
        ps.println();
        // Step 3: Receive the signed token and check it matches
        String signed = s.next();
        // Step 4: Send ACK/NAK depending on whether or not token matches
        sig.initVerify(pub);
        sig.update(buf);
        if (sig.verify(signed.getBytes())) {
            ps.println("ACK");
        } else {
            ps.println("NAK");
        }
        // Step 5: Receive generated token from client and sign it
        String token = s.next();
        sig.initSign(pri);
        sig.update(new BigInteger(token, 16).toByteArray());
        signed = new String(sig.sign());
        // Step 6: Send signed token back to client
        ps.println(signed);
        // Step 7: Check if client ACK or NAKd the signed token
        String resp = s.next();
        if (!resp.equals("ACK")) {
            return false;
        }
        return true;
    }

    private String getIpAddress() {
        String ip = "";
        try {
            Enumeration<NetworkInterface> enumNetworkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (enumNetworkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = enumNetworkInterfaces.nextElement();
                Enumeration<InetAddress> enumInetAddress = networkInterface.getInetAddresses();
                while (enumInetAddress.hasMoreElements()) {
                    InetAddress inetAddress = enumInetAddress.nextElement();
                    if (inetAddress.isSiteLocalAddress()) {
                        ip += "IP Address: " + inetAddress.getHostAddress() + "\n";
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
            return "Error: " + e.toString() + "\n";
        }
        return ip;
    }

    private void doCall() {
        String ip = ipText.getText().toString();
        log += "Calling " + ip + "...\n";
        MainActivity.this.runOnUiThread(new Runnable() {

            @Override
            public void run() {
                logText.setText(log);
                scroll.fullScroll(View.FOCUS_DOWN);
            }
        });
        CallThread callThread = new CallThread(ip);
        callThread.start();
    }

    private void addContact() {
        try {
            String user = userText.getText().toString();
            String userKey = keyText.getText().toString();
            File dir = new File(getApplicationContext().getFilesDir(), "keys");
            if (!dir.exists() || !dir.isDirectory())
                dir.mkdir();
            File file = new File(dir, user);
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(userKey.getBytes());
            fos.close();
            userText.setText("");
            keyText.setText("");
            keys.put(userKey, user);
            users.put(user, userKey);
            Object[] items = keys.values().toArray();
            ArrayAdapter<Object> adapter = new ArrayAdapter<>(this, R.layout.support_simple_spinner_dropdown_item, items);
            callUser.setAdapter(adapter);
            adapter.notifyDataSetChanged();
        } catch (Exception e) {
            log += e.toString() + "\n";
            e.printStackTrace();
        }
    }

    private void loadContacts() {
        try {
            File dir = new File(getApplicationContext().getFilesDir(), "keys");
            if (!dir.exists() || !dir.isDirectory())
                return;

            for (File file : dir.listFiles()) {
                String user = file.getName();
                FileInputStream fis = new FileInputStream(file);
                Scanner s = new Scanner(fis).useDelimiter("\\Z");
                String key = s.next();
                fis.close();
                keys.put(key, user);
                users.put(user, key);
            }
            Object[] items = keys.values().toArray();
            ArrayAdapter<Object> adapter = new ArrayAdapter<>(this, R.layout.support_simple_spinner_dropdown_item, items);
            callUser.setAdapter(adapter);
            adapter.notifyDataSetChanged();
        } catch (Exception e) {
            log += e.toString() + "\n";
            e.printStackTrace();
        }
    }

    private PrivateKey decodePrivateKey(String key) {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(key, Base64.NO_WRAP));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private PublicKey decodePublicKey(String key) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decode(key, Base64.NO_WRAP));
        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private class TalkThread extends Thread {
        Socket socket;

        private TalkThread(Socket sock) {
            this.socket = sock;
        }

        @Override
        public void run() {
            try {
                MediaRecorder rec = new MediaRecorder();
                rec.setAudioSource(MediaRecorder.AudioSource.MIC);
                rec.setOutputFormat(MediaRecorder.OutputFormat.AAC_ADTS);
                rec.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
                FileDescriptor fd = ParcelFileDescriptor.fromSocket(socket).getFileDescriptor();
                rec.setOutputFile(fd);

                MediaPlayer play = new MediaPlayer();
                play.setDataSource(fd);

                rec.prepare();
                play.prepare();

                rec.start();
                play.start();
            } catch (Exception e) {
                e.printStackTrace();
                log += "Error: " + e.toString() + "\n";
            }
        }
    }
}
