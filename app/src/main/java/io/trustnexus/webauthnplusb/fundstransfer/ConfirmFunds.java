/*
 * (c) Copyright 2022 ~ Trust Nexus, Inc.
 * All technologies described here in are "Patent Pending".
 * License information:  http://www.trustnexus.io/license.htm
 *
 * AS LONG AS THIS NOTICE IS MAINTAINED THE LICENSE PERMITS REDISTRIBUTION OR RE-POSTING
 * OF THIS SOURCE CODE TO A PUBLIC REPOSITORY (WITH OR WITHOUT MODIFICATIONS)!
 *
 * Report License Violations:  trustnexus.io@austin.rr.com
 */

package io.trustnexus.webauthnplusb.fundstransfer;

import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.ImageView;
import android.widget.TextView;

import io.trustnexus.webauthnplusb.AboutTnx;
import io.trustnexus.webauthnplusb.ActivatePassword;
import io.trustnexus.webauthnplusb.ActivityBase;
import io.trustnexus.webauthnplusb.Credentials;
import io.trustnexus.webauthnplusb.DataBaseManager;
import io.trustnexus.webauthnplusb.Profile;
import io.trustnexus.webauthnplusb.util.Constants;
import io.trustnexus.webauthnplusb.util.CryptoUtilities;
import io.trustnexus.webauthnplusb.util.Utilities;
import io.trustnexus.webauthnplusb.WebAuthnPlus;

import io.trustnexus.webauthnplusb.R;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class ConfirmFunds extends ActivityBase {

    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_confirm_funds);

        // ----------------------------------------------------------------------------------------------------------------

        TextView messageZero = findViewById(R.id.message_zero);
        TextView messageOne = findViewById(R.id.message_one);

        ImageView imageView = findViewById(R.id.image_credential_icon);

        String userSecurityKeyHex = ((WebAuthnPlus) getApplication()).getUserSecurityKeyHex();
        log("######## userSecurityKeyHex: " + userSecurityKeyHex);

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

        String encryptedPrivateKeyHex = sharedPreferences.getString(this.getString(R.string.crypto_private_key), this.getString(R.string.empty_string));
        log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

        PrivateKey privateKey = CryptoUtilities.retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

        // ----------------------------------------------------------------------------------------------------------------

        NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (notificationManager != null) {
            notificationManager.cancel(Constants.TNX_NOTIFICATION);
        }

        String firebaseDataEncryptedHex = ((WebAuthnPlus) getApplication()).getFirebaseDataEncryptedHex();
        log("################################ firebaseDataEncryptedHex: " + firebaseDataEncryptedHex);

        String firebaseDataEncryptedHashedHex = ((WebAuthnPlus) getApplication()).getFirebaseDataEncryptedHashedHex();
        log("################################ firebaseDataEncryptedHashedHex: " + firebaseDataEncryptedHashedHex);

        try {
            Cipher rsaCipher = Cipher.getInstance(CryptoUtilities.RSA_CIPHER_ALGORITHM);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] transferDataDecryptedBytes = rsaCipher.doFinal(CryptoUtilities.hexStringToByteArray(firebaseDataEncryptedHex));

            String transferDataDecrypted = new String(transferDataDecryptedBytes);
            log("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ transferDataDecrypted: " + transferDataDecrypted);

            String secretKeyHex = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.SECRET_KEY);
            Key secretKey = new SecretKeySpec(CryptoUtilities.hexStringToByteArray(secretKeyHex), CryptoUtilities.SECRET_KEY_ALGORITHM);

            /*
             * Hash the transferDataEncryptedHex using the secretKey.
             */
            Mac macTransferData = Mac.getInstance(CryptoUtilities.MAC_ALGORITHM);
            macTransferData.init(secretKey);
            byte[] transferDataEncryptedHashedBytesTest = macTransferData.doFinal(firebaseDataEncryptedHex.getBytes());

            String transferDataEncryptedHashedHexTest = CryptoUtilities.toHex(transferDataEncryptedHashedBytesTest);
            log("################################ transferDataEncryptedHashedHexTest: " + transferDataEncryptedHashedHexTest);

            /*
             * Test the hashed values to determine the integrity of the message. If the hashed values are equal continue with
             * the process; else return a message:  Constants.MESSAGE_INTEGRITY_COMPROMISED.
             */
            if (firebaseDataEncryptedHashedHex.equalsIgnoreCase(transferDataEncryptedHashedHexTest)) {

                String requestType = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.FIREBASE_MSG_TYPE_KEY);
                log("################################ requestType: " + requestType);

                String credentialType = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.CREDENTIAL_TYPE);
                log("################################ credentialType: " + credentialType);

                DataBaseManager dataBaseManager = null;

                try {
                    dataBaseManager = new DataBaseManager(this);

                    Cursor cursor = dataBaseManager.retrieveCredentialByCredentialType(credentialType);

                    boolean hasResults = cursor.moveToFirst();
                    log("hasResults: " + hasResults);

                    byte[] credentialIconByteArray = cursor.getBlob(cursor.getColumnIndexOrThrow(DataBaseManager.CREDENTIAL_ICON));

                    if (credentialIconByteArray != null && credentialIconByteArray.length > 1) {

                        float scale = getResources().getDisplayMetrics().density;
                        int iconWidth = (int) (scale * 41);
                        int iconHeight = (int) (scale * 27);

                        ByteArrayInputStream imageStream = new ByteArrayInputStream(credentialIconByteArray);
                        Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
                        Bitmap credentialIconBitMapScaled = Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

                        imageView.setImageBitmap(credentialIconBitMapScaled);
                    }

                    String providerName = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.CREDENTIAL_PROVIDER_NAME));
                    TextView providerNameView = findViewById(R.id.provider_name);
                    providerNameView.setText(providerName);

                    String providerUrl = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.DOMAIN_NAME));
                    TextView providerUrlView = findViewById(R.id.provider_url);
                    providerUrlView.setText(providerUrl);

                    String displayName = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.DISPLAY_NAME));
                    TextView displayNameView = findViewById(R.id.display_name);
                    displayNameView.setText(displayName);

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    if (dataBaseManager != null) {
                        dataBaseManager.close();
                    }
                }

                // ------------------------------------------------------------------------------------------------------------

                String recipientName = Utilities.parseJsonNameValuePairs(transferDataDecrypted, Constants.RECIPIENT_NAME);
                log("################################ recipientName: " + recipientName);
                TextView recipientNameView = findViewById(R.id.recipient_name);
                recipientNameView.setText(recipientName);

                String recipientPhoneNumber = Utilities.parseJsonNameValuePairs(transferDataDecrypted, Constants.RECIPIENT_PHONE_NUMBER);
                log("################################ recipientPhoneNumber: " + recipientPhoneNumber);
                TextView recipientPhoneNumberView = findViewById(R.id.recipient_phone_number);
                recipientPhoneNumberView.setText(recipientPhoneNumber);

                String recipientEmail = Utilities.parseJsonNameValuePairs(transferDataDecrypted, Constants.RECIPIENT_EMAIL);
                log("################################ recipientEmail: " + recipientEmail);
                TextView recipientEmailView = findViewById(R.id.recipient_email);
                recipientEmailView.setText(recipientEmail);

                String transferAmount = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.TRANSFER_AMOUNT);
                log("################################ transferAmount: " + transferAmount);
                TextView transferAmountView = findViewById(R.id.transfer_amount);
                transferAmountView.setText(transferAmount);

            } else {
                messageZero.setText(R.string.firebase_message_integrity_compromised);
                messageOne.setText(R.string.firebase_message_integrity_compromised);
            }

            ((WebAuthnPlus) getApplication()).setFirebaseDataEncryptedHex(null);
            ((WebAuthnPlus) getApplication()).setFirebaseDataEncryptedHashedHex(null);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {

        boolean result = super.onCreateOptionsMenu(menu);

        // Use the same options menu as for the Recipients activity.
        MenuInflater menuInflater = getMenuInflater();
        menuInflater.inflate(R.menu.menu_contacts, menu);

        return result;
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        boolean result = super.onOptionsItemSelected(item);

        switch (item.getItemId()) {

            case R.id.credentials:

                if (!checkMaxIdleTimeExceeded()) {
                    Intent credentials = new Intent(this, Credentials.class);
                    startActivity(credentials);
                }

                break;

            case R.id.profile:

                if (!checkMaxIdleTimeExceeded()) {
                    Intent profile = new Intent(this, Profile.class);
                    startActivity(profile);
                }

                break;

            case R.id.about_tnx:

                Intent aboutTnx = new Intent(this, AboutTnx.class);
                startActivity(aboutTnx);

                break;

            case R.id.exit:

                ((WebAuthnPlus) getApplication()).setExitValues();

                Intent activate = new Intent(this, ActivatePassword.class);
                activate.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                startActivity(activate);

                moveTaskToBack(true);
                break;

            default:
                break;
        }

        return result;
    }
}
