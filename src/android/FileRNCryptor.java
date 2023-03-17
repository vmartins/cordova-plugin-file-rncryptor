package at.lehklu.android;

import org.cryptonode.jncryptor.*;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;

import java.util.Base64;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;

import android.os.Build;
import android.util.Log;

/**
 * This class encrypts and decrypts files using
 * the jncryptor lib.
 *
 */
public class FileRNCryptor extends CordovaPlugin
{
    private static final String TAG = "FileRNCryptor";

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException
    {
        final String data = args.getString(0);
        final String password = args.getString(1);

        if (action.equals("encryptText")) {
            this.encryptText(data, password, callbackContext);
        } else if (action.equals("decryptText")) {
            this.decryptText(data, password, callbackContext);
        } else if (action.equals("encrypt")) {
            this.encrypt(data, password, callbackContext);
        } else if (action.equals("decrypt")) {
            this.decrypt(data, password, callbackContext);
        } else {
            return false;
        }

        return true;
    }

    /**
     * Encrypt text
     *
     */
    private void encryptText(String text, String password, CallbackContext callbackContext)
    {
        try {
            JNCryptor cryptor = new AES256JNCryptor();
            byte[] encryptData = cryptor.encryptData(text.getBytes(StandardCharsets.UTF_8), password.toCharArray());
            String base64Encoded;

            if (Build.VERSION.SDK_INT >= 26) {
                base64Encoded = Base64.getEncoder().encodeToString(encryptData);
            } else {
                base64Encoded = android.util.Base64.encodeToString(encryptData, android.util.Base64.DEFAULT);
            }

            callbackContext.success(base64Encoded);
        } catch (SecurityException e) {
            Log.d(TAG, "encryptText SecurityException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (CryptorException e) {
            Log.d(TAG, "encryptText CryptorException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        }
    }

    /**
     * Decrypt text
     *
     */
    private void decryptText(String text, String password, CallbackContext callbackContext)
    {
        try {
            JNCryptor cryptor = new AES256JNCryptor();

            byte[] base64Decoded;
            if (Build.VERSION.SDK_INT >= 26) {
                base64Decoded = Base64.getDecoder().decode(text);
            } else {
                base64Decoded = android.util.Base64.decode(text, android.util.Base64.DEFAULT);
            }

            byte[] decryptData = cryptor.decryptData(base64Decoded, password.toCharArray());

            callbackContext.success(new String(decryptData, StandardCharsets.UTF_8));
        } catch (SecurityException e) {
            Log.d(TAG, "decryptText SecurityException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (CryptorException e) {
            Log.d(TAG, "decryptText CryptorException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        }
    }

    /**
     * Encrypt
     *
     */
    private void encrypt(String path, String password, CallbackContext callbackContext)
    {
        try {
            FileInputStream iStream = new FileInputStream(path);
            FileChannel iChannel = iStream.getChannel();

            if (Integer.MAX_VALUE<iChannel.size()) {
                Log.d(TAG, "encrypt: file too large");
                callbackContext.error("encrypt: file too large");
                return;
            }

            ByteBuffer buffer = ByteBuffer.allocate((int) iChannel.size());
            iChannel.read(buffer);

            byte[] data = buffer.array();
            iStream.close();

            JNCryptor cryptor = new AES256JNCryptor();
            byte[] encryptData = cryptor.encryptData(data, password.toCharArray());
            FileOutputStream oStream = new FileOutputStream(path);
            FileChannel oChannel = oStream.getChannel();
            oChannel.write(ByteBuffer.wrap(encryptData));
            oStream.close();

            callbackContext.success(path);
        } catch (IOException e) {
            Log.d(TAG, "encrypt IOException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (OutOfMemoryError e) {
            Log.d(TAG, "encrypt OutOfMemoryError: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (SecurityException e) {
            Log.d(TAG, "encrypt SecurityException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (CryptorException e) {
            Log.d(TAG, "encrypt CryptorException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        }
    }

    /**
     * Decrypt
     *
     */
    private void decrypt(String path, String password, CallbackContext callbackContext)
    {
        try {
            FileInputStream iStream = new FileInputStream(path);
            FileChannel iChannel = iStream.getChannel();

            if (Integer.MAX_VALUE<iChannel.size()) {
                Log.d(TAG, "decrypt: file too large");
                callbackContext.error("encrypt: file too large");
                return;
            }

            ByteBuffer buffer = ByteBuffer.allocate((int) iChannel.size());
            iChannel.read(buffer);

            byte[] data = buffer.array();
            iStream.close();

            JNCryptor cryptor = new AES256JNCryptor();
            byte[] decryptData = cryptor.decryptData(data, password.toCharArray());
            FileOutputStream oStream = new FileOutputStream(path);
            FileChannel oChannel = oStream.getChannel();
            oChannel.write(ByteBuffer.wrap(decryptData));
            oStream.close();

            callbackContext.success(path);
        } catch (IOException e) {
            Log.d(TAG, "decrypt IOException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (OutOfMemoryError e) {
            Log.d(TAG, "decrypt OutOfMemoryError: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (SecurityException e) {
            Log.d(TAG, "decrypt SecurityException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        } catch (CryptorException e) {
            Log.d(TAG, "decrypt CryptorException: " + e.getMessage());
            callbackContext.error(e.getMessage());
        }
    }
}
