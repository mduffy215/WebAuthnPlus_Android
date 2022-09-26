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

import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;

import io.trustnexus.webauthnplusb.AboutTnx;
import io.trustnexus.webauthnplusb.ActivatePassword;
import io.trustnexus.webauthnplusb.ActivityBase;
import io.trustnexus.webauthnplusb.Credentials;
import io.trustnexus.webauthnplusb.DataBaseManager;
import io.trustnexus.webauthnplusb.Profile;
import io.trustnexus.webauthnplusb.WebAuthnPlus;
import io.trustnexus.webauthnplusb.util.Constants;
import io.trustnexus.webauthnplusb.util.CryptoUtilities;
import io.trustnexus.webauthnplusb.util.Utilities;
import io.trustnexus.webauthnplusb.R;

public class ReceiveFunds extends ActivityBase implements OnClickListener {

    private PrivateKey privateKey;
    private String retrieveTransactionUuidUrl;
    private String receiveFundsUrl;
    private String acceptFundsUrl;
    private String publicKeyUuid;
    private String publicKeyHex;
    private String userUuid;
    private String credentialType;
    private boolean initiateFundsTransferFlag;
    private boolean initiateFundsAcceptanceFlag;
    private ProgressDialog progressDialog;

    private String jsonCredential;
    private String jsonFundsTransfer;
    private TextView sendingBankView;
    private TextView senderNameView;
    private TextView senderPhoneNumberView;
    private TextView senderEmailView;
    private TextView transferAmountView;
    private TextView messageOne;

    private Button acceptButton;
    private Button cancelButton;
    private Boolean fundsAccepted = false;

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_receive_funds);

        // ----------------------------------------------------------------------------------------------------------------

        ImageView imageView = findViewById(R.id.image_credential_icon);

        String userSecurityKeyHex = ((WebAuthnPlus) getApplication()).getUserSecurityKeyHex();
        log("######## userSecurityKeyHex: " + userSecurityKeyHex);

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

        String encryptedPrivateKeyHex = sharedPreferences.getString(this.getString(R.string.crypto_private_key), this.getString(R.string.empty_string));
        log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

        privateKey = CryptoUtilities.retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

        credentialType = Constants.DEFAULT_FINANCIAL_CREDENTIAL_TYPE;
        log("credentialType: " + credentialType);

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

            sendingBankView = findViewById(R.id.sending_bank);
            senderNameView = findViewById(R.id.sender_name);
            senderPhoneNumberView = findViewById(R.id.sender_phone_number);
            senderEmailView = findViewById(R.id.sender_email);
            transferAmountView = findViewById(R.id.transfer_amount);
            messageOne = findViewById(R.id.message_one);

            String encryptedJsonCredential = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.ENCRYPTED_JSON_CREDENTIAL));
            jsonCredential = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedJsonCredential);
            log("jsonCredential: " + jsonCredential);

            retrieveTransactionUuidUrl = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.RETRIEVE_TRANSACTION_UUID_URL));
            log("retrieveTransactionUuidUrl: " + retrieveTransactionUuidUrl);

            receiveFundsUrl = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.RECEIVE_FUNDS_URL));
            log("receiveFundsUrl: " + receiveFundsUrl);

            acceptFundsUrl = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.ACCEPT_FUNDS_URL));
            log("acceptFundsUrl: " + acceptFundsUrl);

            publicKeyUuid = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.PUBLIC_KEY_UUID));
            log("publicKeyUuid: " + publicKeyUuid);

            publicKeyHex = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.PUBLIC_KEY));
            log("publicKeyHex: " + publicKeyHex);

            String encryptedUserUuid = cursor.getString(cursor.getColumnIndexOrThrow(DataBaseManager.ENCRYPTED_USER_UUID));
            userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedUserUuid);
            log("userUuid: " + userUuid);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (dataBaseManager != null) {
                dataBaseManager.close();
            }
        }

        acceptButton = findViewById(R.id.accept_button);
        acceptButton.setOnClickListener(this);

        cancelButton = findViewById(R.id.cancel_button);
        cancelButton.setOnClickListener(this);

        // ----------------------------------------------------------------------------------------------------------------

        progressDialog = new ProgressDialog(this);
        progressDialog.setCancelable(false);
        progressDialog.setTitle(getString(R.string.app_name));
        progressDialog.setMessage(getString(R.string.funds_transfer_retrieving_data));
        progressDialog.setIndeterminate(false);
        progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        progressDialog.setProgress(0);
        progressDialog.show();

        // --------------------------------------------------------------------------------------------------------

        String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey, publicKeyUuid, publicKeyHex);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {retrieveTransactionUuidUrl, urlParameters, transferKeyHex};

        /*
         * This method makes a call to the web application.  Like almost all methods that make a call to the web
         * application a call is first made to get a TransactionUuid (which adds security to the process), then
         * from that inner class control is transferred to another inner class based on a flag.
         */
        initiateFundsTransferFlag = true;

        ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
        processRetrieveTransactionUuid.execute(urlStrings);
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

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void onClick(View view) {

        if (!checkMaxIdleTimeExceeded()) {

            /*
             * There are two buttons:  Send and Clear
             */
            switch (view.getId()) {

                case R.id.accept_button:

                    if (!fundsAccepted) {

                        fundsAccepted = true;

                        //String phoneNumberSms = recipientPhoneNumber.replace("-", "");

                        //SmsManager smsManager = SmsManager.getDefault();
                        //smsManager.sendTextMessage(phoneNumberSms, null, "This is a test!", null, null);

                        // ----------------------------------------------------------------------------------------------------------

                        String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey, publicKeyUuid, publicKeyHex);

                        assert paramStrings != null;
                        String urlParameters = paramStrings[0];
                        String transferKeyHex = paramStrings[1];

                        String[] urlStrings = {retrieveTransactionUuidUrl, urlParameters, transferKeyHex};

                        /*
                         * This method makes a call to the web application.  Like almost all methods that make a call to the web
                         * application a call is first made to get a TransactionUuid (which adds security to the process), then
                         * from that inner class control is transferred to another inner class based on a flag.
                         */
                        initiateFundsAcceptanceFlag = true;

                        ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
                        processRetrieveTransactionUuid.execute(urlStrings);
                    }

                    break;

                case R.id.cancel_button:

                    Intent credentials = new Intent(this, Credentials.class);
                    startActivity(credentials);

                    break;

                default:
                    break;
            }
        }
    }

    // ----------------------------------------------------------------------------------------------------------------

    public boolean isNetworkAvailable() {

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = null;
        if (connectivityManager != null) {
            networkInfo = connectivityManager.getActiveNetworkInfo();
        }

        return networkInfo != null && networkInfo.isConnected();
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessRetrieveTransactionUuid extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<ReceiveFunds> activityReference;

        // only retain a weak reference to the activity
        ProcessRetrieveTransactionUuid(ReceiveFunds context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            ReceiveFunds receiveFunds = activityReference.get();

            if (!receiveFunds.isNetworkAvailable()) {
                return receiveFunds.getString(R.string.network_unavailable);
            } else {

                String targetUrlString = urlStrings[0];
                String urlParameters = urlStrings[1];
                String transferKeyHex = urlStrings[2];

                URL targetUrl;
                HttpURLConnection connection = null;

                try {
                    targetUrl = new URL(targetUrlString);

                    connection = (HttpURLConnection) targetUrl.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, receiveFunds);
                    log("responseString::" + responseString + "::");

                    return Utilities.parseNameValuePairs(responseString, Constants.TRANSACTION_UUID);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            /*
             * A ProgressDialog.STYLE_SPINNER is initiated in the create() method of this Intent.
             */
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String transactionUuid) {

            ReceiveFunds receiveFunds = activityReference.get();

            log("RESULT::" + transactionUuid + "::");

            receiveFunds.progressDialog.dismiss();

            // --------------------------------------------------------------------------------------------------------------

            if (receiveFunds.initiateFundsTransferFlag) {

                receiveFunds.initiateFundsTransferFlag = false;

                String sendingBank = ((WebAuthnPlus) receiveFunds.getApplication()).getSmsSender();
                log("######## sendingBank: " + sendingBank);
                String fundsTransferUuid = ((WebAuthnPlus) receiveFunds.getApplication()).getSmsRef();
                log("######## fundsTransferUuid: " + fundsTransferUuid);

                String transferData = Constants.USER_UUID + "=" + receiveFunds.userUuid + "&"
                        + Constants.SENDER + "=" + sendingBank + "&"
                        + Constants.REFERENCE + "=" + fundsTransferUuid + "&"
                        + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                        + Constants.TRANSACTION_UUID_SIGNED + "="
                        + CryptoUtilities.generateSignedHex(transactionUuid, receiveFunds.privateKey) + "&";

                String[] paramStrings = CryptoUtilities.generateParams_ReceiveFunds(transferData, receiveFunds.publicKeyUuid, receiveFunds.publicKeyHex);

                assert paramStrings != null;
                String urlParameters = paramStrings[0];
                String transferKeyHex = paramStrings[1];

                String[] urlStrings = {receiveFunds.receiveFundsUrl, urlParameters, transferKeyHex};

                ProcessReceiveFunds processReceiveFunds = new ProcessReceiveFunds(receiveFunds);
                processReceiveFunds.execute(urlStrings);

            } else if (receiveFunds.initiateFundsAcceptanceFlag) {

                receiveFunds.initiateFundsAcceptanceFlag = false;

                String jsonFundsTransfer = receiveFunds.jsonFundsTransfer.substring(0, receiveFunds.jsonFundsTransfer.lastIndexOf(","));

                jsonFundsTransfer += "\n\n\"" + Constants.TIMESTAMP + "\":\"" + Utilities.generateIsoTimestamp(System.currentTimeMillis()) + "\",";
                jsonFundsTransfer += "\n\"" + Constants.TRANSACTION_UUID + "\":\"" + transactionUuid + "\",";

                jsonFundsTransfer += "\n\n" + receiveFunds.jsonCredential;

                jsonFundsTransfer += "\n\n\"" + Constants.RECIPIENT_SECURE_HASH_ALGORITHM + "\":\"" + CryptoUtilities.SECURE_HASH_ALGORITHM + "\",";
                jsonFundsTransfer += "\n\"" + Constants.RECIPIENT_SIGNATURE_ALGORITHM + "\":\"" + CryptoUtilities.SIGNATURE_ALGORITHM + "\",";

                String recipientHash = CryptoUtilities.digest(jsonFundsTransfer);
                log("recipientHash::" + recipientHash + "::");

                assert recipientHash != null;
                String recipientSignedHash = CryptoUtilities.generateSignedHex(recipientHash, receiveFunds.privateKey);
                log("recipientSignedHash::" + recipientSignedHash + "::");

                jsonFundsTransfer += "\n\"" + Constants.RECIPIENT_HASH + "\":\"" + recipientHash + "\", "
                        + "\n\"" + Constants.RECIPIENT_SIGNED_HASH + "\":\"" + recipientSignedHash + "\", ";

                // ------------------------------------------------------------------------------------------------------------

                /*
                 * Thx Travis!
                 * https://stackoverflow.com/questions/8888654/android-set-max-length-of-logcat-messages
                 */
                if (jsonFundsTransfer.length() > 4000) {
                    log("RESULT LENGTH::" + jsonFundsTransfer.length() + "::");
                    int chunkCount = jsonFundsTransfer.length() / 4000;
                    for (int i = 0; i <= chunkCount; i++) {
                        int max = 4000 * (i + 1);
                        if (max >= jsonFundsTransfer.length()) {
                            log("jsonFundsTransfer:: " + (i + 1) + " of " + (chunkCount + 1) + ":" + jsonFundsTransfer.substring(4000 * i));
                        } else {
                            log("jsonFundsTransfer:: " + (i + 1) + " of " + (chunkCount + 1) + ":" + jsonFundsTransfer.substring(4000 * i, max));
                        }
                    }
                } else {
                    log("jsonFundsTransfer::" + jsonFundsTransfer + "::");
                }

                // ------------------------------------------------------------------------------------------------------------

                String transferData = Constants.CREDENTIAL_TYPE + "=" + receiveFunds.credentialType + "&"
                        + Constants.USER_UUID + "=" + receiveFunds.userUuid + "&"
                        + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                        + Constants.TRANSACTION_UUID_SIGNED + "="
                        + CryptoUtilities.generateSignedHex(transactionUuid, receiveFunds.privateKey) + "&"
                        + Constants.JSON_FUNDS_TRANSFER + "=" + jsonFundsTransfer + "&";

                String[] paramStrings = CryptoUtilities.generateParams_AcceptFunds(transferData, receiveFunds.publicKeyUuid, receiveFunds.publicKeyHex);

                assert paramStrings != null;
                String urlParameters = paramStrings[0];
                String transferKeyHex = paramStrings[1];

                String[] urlStrings = {receiveFunds.acceptFundsUrl, urlParameters, transferKeyHex};

                ProcessAcceptFunds processAcceptFunds = new ProcessAcceptFunds(receiveFunds);
                processAcceptFunds.execute(urlStrings);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessReceiveFunds extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<ReceiveFunds> activityReference;

        // only retain a weak reference to the activity
        ProcessReceiveFunds(ReceiveFunds context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            ReceiveFunds receiveFunds = activityReference.get();

            if (!receiveFunds.isNetworkAvailable()) {
                return receiveFunds.getString(R.string.network_unavailable);
            } else {

                String targetURL = urlStrings[0];
                String urlParameters = urlStrings[1];
                String transferKeyHex = urlStrings[2];

                URL url;
                HttpURLConnection connection = null;

                try {
                    url = new URL(targetURL);

                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, receiveFunds);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            ReceiveFunds receiveFunds = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            receiveFunds.progressDialog = new ProgressDialog(receiveFunds);
            receiveFunds.progressDialog.setCancelable(true);
            receiveFunds.progressDialog.setTitle(receiveFunds.getString(R.string.app_name));
            receiveFunds.progressDialog.setMessage(receiveFunds.getString(R.string.receiving_funds));
            receiveFunds.progressDialog.setIndeterminate(false);
            receiveFunds.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            receiveFunds.progressDialog.setProgress(0);
            receiveFunds.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            ReceiveFunds receiveFunds = activityReference.get();

            receiveFunds.jsonFundsTransfer = result;

            /*
             * Thx Travis!
             * https://stackoverflow.com/questions/8888654/android-set-max-length-of-logcat-messages
             */
            if (result.length() > 4000) {
                log("RESULT LENGTH::" + result.length() + "::");
                int chunkCount = result.length() / 4000;
                for (int i = 0; i <= chunkCount; i++) {
                    int max = 4000 * (i + 1);
                    if (max >= result.length()) {
                        log("RESULT " + (i + 1) + " of " + (chunkCount + 1) + ":" + result.substring(4000 * i));
                    } else {
                        log("RESULT " + (i + 1) + " of " + (chunkCount + 1) + ":" + result.substring(4000 * i, max));
                    }
                }
            } else {
                log("RESULT::" + result + "::");
            }

            receiveFunds.progressDialog.dismiss();

            receiveFunds.sendingBankView.setText(Utilities.parseJsonNameValuePairs(result, Constants.SENDING_BANK_NAME));
            receiveFunds.senderNameView.setText(Utilities.parseJsonNameValuePairs(result, Constants.SENDER_NAME));
            receiveFunds.senderPhoneNumberView.setText(Utilities.parseJsonNameValuePairs(result, Constants.SENDER_PHONE_NUMBER));
            receiveFunds.senderEmailView.setText(Utilities.parseJsonNameValuePairs(result, Constants.SENDER_EMAIL));
            receiveFunds.transferAmountView.setText(Utilities.parseJsonNameValuePairs(result, Constants.TRANSFER_AMOUNT));
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessAcceptFunds extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<ReceiveFunds> activityReference;

        // only retain a weak reference to the activity
        ProcessAcceptFunds(ReceiveFunds context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            ReceiveFunds receiveFunds = activityReference.get();

            if (!receiveFunds.isNetworkAvailable()) {
                return receiveFunds.getString(R.string.network_unavailable);
            } else {

                String targetURL = urlStrings[0];
                String urlParameters = urlStrings[1];
                String transferKeyHex = urlStrings[2];

                URL url;
                HttpURLConnection connection = null;

                try {
                    url = new URL(targetURL);

                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, receiveFunds);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            ReceiveFunds receiveFunds = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            receiveFunds.progressDialog = new ProgressDialog(receiveFunds);
            receiveFunds.progressDialog.setCancelable(true);
            receiveFunds.progressDialog.setTitle(receiveFunds.getString(R.string.app_name));
            receiveFunds.progressDialog.setMessage(receiveFunds.getString(R.string.accepting_funds));//
            receiveFunds.progressDialog.setIndeterminate(false);
            receiveFunds.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            receiveFunds.progressDialog.setProgress(0);
            receiveFunds.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            log("RESULT::" + result + "::");

            ReceiveFunds receiveFunds = activityReference.get();

            receiveFunds.progressDialog.dismiss();

            receiveFunds.messageOne.setVisibility(TextView.VISIBLE);
            receiveFunds.messageOne.setText(result);
            receiveFunds.acceptButton.setBackground(ContextCompat.getDrawable(receiveFunds, R.drawable.button_gradient2));
            receiveFunds.cancelButton.setText(R.string.clear);
        }
    }
}



















