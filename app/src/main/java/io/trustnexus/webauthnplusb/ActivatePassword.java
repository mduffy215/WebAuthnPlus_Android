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

package io.trustnexus.webauthnplusb;

import android.app.DialogFragment;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.messaging.FirebaseMessaging;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.util.List;

import io.trustnexus.webauthnplusb.distributedledger.Signature;
import io.trustnexus.webauthnplusb.fundstransfer.ConfirmFunds;
import io.trustnexus.webauthnplusb.fundstransfer.ReceiveFunds;
import io.trustnexus.webauthnplusb.util.Constants;
import io.trustnexus.webauthnplusb.util.CryptoUtilities;
import io.trustnexus.webauthnplusb.util.Utilities;

public class ActivatePassword extends ActivityBase implements OnClickListener {

    private String transferKeyHex;
    private String secretKeyHex;

    private EditText password;
    private String passwordValue;
    private EditText verifyPassword;
    private TextView activateMessage;
    private TextView message;

    private boolean userCreated;
    private ProgressDialog progressDialog;
    private String userUuid;
    private PrivateKey privateKey;
    private String firebaseMsgType;
    private String firebaseDeviceId;
    private boolean receiveFunds;

    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_activate_password);

        // ----------------------------------------------------------------------------------------------------------------

        new Eula(this).show();

        ImageView applicationIcon = findViewById(android.R.id.home);
        FrameLayout.LayoutParams applicationIconLayoutParams = (FrameLayout.LayoutParams) applicationIcon.getLayoutParams();
        applicationIconLayoutParams.topMargin = 0;
        applicationIconLayoutParams.bottomMargin = 0;
        applicationIcon.setLayoutParams(applicationIconLayoutParams);

        this.activateMessage = findViewById(R.id.activate_message);

        // ----------------------------------------------------------------------------------------------------------------

        this.password = findViewById(R.id.password);
        TextView verifyPasswordLabel = findViewById(R.id.verify_password_label);
        this.verifyPassword = findViewById(R.id.verify_password);

        // ----------------------------------------------------------------------------------------------------------------

        Button activateButton = findViewById(R.id.activate);
        activateButton.setOnClickListener(this);

        this.message = findViewById(R.id.message);
        this.message.setVisibility(TextView.GONE);

        // ----------------------------------------------------------------------------------------------------------------

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);
        String userCreatedString = sharedPreferences.getString(getString(R.string.user_created_key), getString(R.string.empty_string));

        log("################ userCreatedString: " + userCreatedString);

        assert userCreatedString != null;
        if (userCreatedString.equals(getString(R.string.user_created))) {

            userCreated = true;

            activateMessage.setText(getString(R.string.activate_message));
            verifyPasswordLabel.setVisibility(TextView.GONE);
            this.verifyPassword.setVisibility(TextView.GONE);

        } else {
            userCreated = false;
            activateMessage.setText(getString(R.string.activate_create));
        }

        password.requestFocus();

        if (password.requestFocus()) {
            getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE);
        }

        long lastInteraction = ((WebAuthnPlus) getApplication()).getLastInteraction();
        log("lastInteraction: " + lastInteraction);

        /*
         * If the user exits by touching the "Exit" options menu then lastInteraction = 0.
         * If the application exits because the MAX_IDLE_TIME_EXCEEDED then lastInteraction = MAX_IDLE_TIME.
         *
         * Either of these setting will cause checkMaxIdleTimeExceeded() to return true.
         *
         * By setting the lastInteraction = MAX_IDLE_TIME when MAX_IDLE_TIME_EXCEEDED it gives us a flag that tells us the
         * application exited because the MAX_IDLE_TIME_EXCEEDED.
         *
         * When activating the application through this activity, only show the MAX_IDLE_TIME_EXCEEDED dialog if the
         * application exited because the MAX_IDLE_TIME_EXCEEDED.
         */

        if (lastInteraction == Constants.MAX_IDLE_TIME) {
            DialogFragment alertDialogFragmentMessage = AlertDialogFragmentMessage.newInstance(Constants.MAX_IDLE_TIME_EXCEEDED);
            alertDialogFragmentMessage.show(getFragmentManager(), "dialog");
        }

        // ----------------------------------------------------------------------------------------------------------------

        Uri data = getIntent().getData();

        if (data != null) {

            log("################ data: " + data.getPath());

            String scheme = data.getScheme();
            log("################ scheme: " + scheme);

            String host = data.getHost();
            log("################ host: " + host);

            List<String> pathSegments = data.getPathSegments();
            log("################ pathSegments: " + pathSegments.size());

            String sender = data.getQueryParameter(Constants.SENDER);
            log("################ sender: " + sender);
            ((WebAuthnPlus) getApplication()).setSmsSender(sender);

            String ref = data.getQueryParameter(Constants.REFERENCE);
            log("################ ref: " + ref);
            ((WebAuthnPlus) getApplication()).setSmsRef(ref);

            receiveFunds = true;

        } else {
            ((WebAuthnPlus) getApplication()).setSmsSender(null);
            ((WebAuthnPlus) getApplication()).setSmsRef(null);
        }

        // ----------------------------------------------------------------------------------------------------------------

        Bundle extras = getIntent().getExtras();

        /*
         * The only case for ActivatePassword where extras != null is when there has been a Firebase notification.
         *
         * If a Firebase notification comes in and the app is closed or not in focus, the notification is sent to the extras
         * Bundle of the main activity, ActivatePassword.  If a Firebase notification comes in and the app is open, the notification
         * is sent to TnxFirebaseMessagingService.onMessageReceived(...).
         */
        boolean resetApplicationScopeVariables = true;

        if (extras != null) {
            for (String key : getIntent().getExtras().keySet()) {

                if (key.equals("google.sent_time")) {
                    long value = getIntent().getExtras().getLong(key);
                    log("################ Extras:: Key: " + key + " Value: " + value);
                } else {
                    String value = getIntent().getExtras().getString(key);
                    log("################ Extras:: Key: " + key + " Value: " + value);
                }
            }

            ((WebAuthnPlus) getApplication()).setFirebaseDataEncryptedHex(getIntent().getExtras().getString(Constants.TRANSFER_DATA_ENCRYPTED_HEX));
            log("################################ firebaseDataEncryptedHex: " + ((WebAuthnPlus) getApplication()).getFirebaseDataEncryptedHex());

            ((WebAuthnPlus) getApplication()).setFirebaseDataEncryptedHashedHex(getIntent().getExtras().getString(Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX));
            log("################################ firebaseDataEncryptedHashedHex: " + ((WebAuthnPlus) getApplication()).getFirebaseDataEncryptedHashedHex());

            firebaseMsgType = getIntent().getExtras().getString(Constants.FIREBASE_MSG_TYPE_KEY);
            log("################################ firebaseMsgType: " + firebaseMsgType);

            /*
             * If the user is still signed on go directly to the activity.
             */
            if (lastInteraction != 0 && lastInteraction != Constants.MAX_IDLE_TIME && !checkMaxIdleTimeExceeded()) {

                log("################################ Go directly to Intent.");

                //Do not reset the application scope variable if the user is still signed on.
                resetApplicationScopeVariables = false;

                if (firebaseMsgType != null) {
                    switch (firebaseMsgType) {
                        case Constants.FIREBASE_MSG_TYPE_CREATE_CREDENTIAL:
                        case Constants.FIREBASE_MSG_TYPE_SIGN_ON:

                            Intent credentials = new Intent(this, Credentials.class);
                            startActivity(credentials);

                            break;
                        case Constants.FIREBASE_MSG_TYPE_CONFIRM_FUNDS_TRANSFER:

                            Intent confirmFunds = new Intent(this, ConfirmFunds.class);
                            startActivity(confirmFunds);

                            break;
                        case Constants.FIREBASE_MSG_TYPE_SIGN_DISTRIBUTED_LEDGER:

                            Intent signature = new Intent(this, Signature.class);
                            startActivity(signature);
                            break;
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        /*
         * Only reset transferDataEncryptedHex and transferDataEncryptedHashedHex in the Credential activity after processes
         * have completed.  We do not want to clear these variables if MAX_IDLE_TIME has been exceeded and the Credential
         * activity processes have not completed.  We do want to clear these variables if the user deliberately EXITS the
         * application.
         */
        if (resetApplicationScopeVariables) {

            ((WebAuthnPlus) getApplication()).setSignOnSuccessful(false);

            ((WebAuthnPlus) getApplication()).setUserSecurityKeyHex(null);
            ((WebAuthnPlus) getApplication()).setLastSignOnCredentialType(null);
            ((WebAuthnPlus) getApplication()).setCreateCredentialType(null);
            ((WebAuthnPlus) getApplication()).setCreateCredentialResult(null);
            ((WebAuthnPlus) getApplication()).setVerificationCodeValue(null);

            ((WebAuthnPlus) getApplication()).setLastInteraction(0L);
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void onClick(View view) {

        passwordValue = this.password.getText().toString();
        String verifyPasswordValue = this.verifyPassword.getText().toString();

        if (view.getId() == R.id.activate) {

            if (userCreated) {

                this.message.setVisibility(TextView.GONE);

                SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);
                String[] paramStrings = CryptoUtilities.generateParams_MobileApplicationSignOn(passwordValue, sharedPreferences, ActivatePassword.this);

                assert paramStrings != null;
                String urlParameters = paramStrings[0];
                transferKeyHex = paramStrings[1];
                secretKeyHex = paramStrings[2];

                String[] urlStrings = {Constants.MOBILE_APPLICATION_SIGN_ON_URL, urlParameters};

                /*
                 * The ProcessSignOn is a retrieval of the user's security key associated with the obfuscated identifier
                 * created by the user's password and stored SALT value.
                 */
                ProcessSignOn processSignOn = new ProcessSignOn(this);
                processSignOn.execute(urlStrings);

            } else {

                if (passwordValue == null || passwordValue.length() < 6) {

                    /*
                     * The initial rule is that the password must be at least six characters, numbers or values.
                     * Code for more complex password requirements would be created here.
                     */

                    activateMessage.setTypeface(null, Typeface.BOLD);
                    activateMessage.setTextColor(ContextCompat.getColor(this, R.color.warning_color));
                    activateMessage.setText(R.string.password_not_valid);

                    this.password.setText("");

                } else {

                    if (passwordValue.equals(verifyPasswordValue)) {

                        ((WebAuthnPlus) getApplication()).setPasswordValue(passwordValue);

                        /*
                         * Send the user off to create his/her profile and activate his/her account by creating the user's
                         * public key and user security key (the key used to encrypt and decrypt values on the mobile device).
                         */
                        Intent profile = new Intent(this, Profile.class);
                        startActivity(profile);

                    } else {
                        DialogFragment newFragment = AlertDialogFragmentMessage.newInstance(Constants.PASSWORD_VERIFICATION_FAILED);
                        newFragment.show(getFragmentManager(), "dialog");

                        this.password.setText("");
                        this.verifyPassword.setText("");
                    }
                }
            }

            ((WebAuthnPlus) getApplication()).setLastInteraction(System.currentTimeMillis());
        }
    }

    // ----------------------------------------------------------------------------------------------------------------

    public boolean isNetworkAvailable() {

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = null;
        if (connectivityManager != null) {
            networkInfo = connectivityManager.getActiveNetworkInfo();
        }

        return networkInfo != null && networkInfo.isConnected();
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {

        boolean result = super.onCreateOptionsMenu(menu);

        MenuInflater menuInflater = getMenuInflater();
        menuInflater.inflate(R.menu.menu_activate_password, menu);

        return result;
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        boolean result = super.onOptionsItemSelected(item);

        switch (item.getItemId()) {

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

    /*
     * Thx mindroit!
     * https://stackoverflow.com/questions/1819142/how-should-i-validate-an-e-mail-address
     */
    public static boolean isValidEmail(CharSequence target) {
        if (TextUtils.isEmpty(target)) {
            return false;
        } else {
            return android.util.Patterns.EMAIL_ADDRESS.matcher(target).matches();
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessSignOn extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<ActivatePassword> activityReference;

        // only retain a weak reference to the activity
        ProcessSignOn(ActivatePassword context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            ActivatePassword activatePassword = activityReference.get();

            if (!activatePassword.isNetworkAvailable()) {
                return activatePassword.getString(R.string.network_unavailable);
            } else {

                String targetURL = urlStrings[0];
                String urlParameters = urlStrings[1];

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

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), activatePassword.transferKeyHex, activatePassword);

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

            ActivatePassword activatePassword = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            activatePassword.progressDialog = new ProgressDialog(activatePassword);
            activatePassword.progressDialog.setCancelable(false);
            activatePassword.progressDialog.setTitle(activatePassword.getString(R.string.app_name));
            activatePassword.progressDialog.setMessage(activatePassword.getString(R.string.signingOn));
            activatePassword.progressDialog.setIndeterminate(false);
            activatePassword.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            activatePassword.progressDialog.setProgress(0);
            activatePassword.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            ActivatePassword activatePassword = activityReference.get();

            log("RESULT::" + result + "::");

            activatePassword.progressDialog.dismiss();

            if (result == null) {
                result = activatePassword.getString(R.string.problem_with_authentication_server);
            }

            if (result.contains(Constants.SIGN_ON_SUCCESSFUL)) {

                String wrappedUserSecurityKeyHex = Utilities.parseNameValuePairs(result, Constants.USER_SECURITY_KEY_ENCRYPTED);
                log("wrappedUserSecurityKeyHex: " + wrappedUserSecurityKeyHex);

                String userSecurityKeyHexEncrypted = CryptoUtilities.unwrapKey(activatePassword.transferKeyHex, wrappedUserSecurityKeyHex);
                log("################ userSecurityKeyHexEncrypted: " + userSecurityKeyHexEncrypted);

                String userSecurityKeyHex = CryptoUtilities.decrypt(activatePassword.secretKeyHex, userSecurityKeyHexEncrypted);
                log("################ userSecurityKeyHexEncrypted: " + userSecurityKeyHexEncrypted);

                ((WebAuthnPlus) activatePassword.getApplication()).setSignOnSuccessful(true);
                ((WebAuthnPlus) activatePassword.getApplication()).setUserSecurityKeyHex(userSecurityKeyHex);
                ((WebAuthnPlus) activatePassword.getApplication()).setPasswordValue(activatePassword.passwordValue);
                ((WebAuthnPlus) activatePassword.getApplication()).setLastInteraction(System.currentTimeMillis());

                /*
                 * The sign on is successful; however, we may need to go back to the server to update the  .
                 * If we do, the next intent will be determined in ProcessUpdateFirebaseDeviceId.onPostExecute().
                 * If we do not, the next intent will be determined by the firebaseMsgType
                 */
                FirebaseMessaging.getInstance().getToken()
                        .addOnCompleteListener(new OnCompleteListener<String>() {
                            @Override
                            public void onComplete(@NonNull Task<String> task) {
                                if (!task.isSuccessful()) {
                                    log("Fetching FCM registration token failed: " + task.getException());
                                    return;
                                }
                                // Get new FCM registration token
                                activatePassword.firebaseDeviceId = task.getResult();
                                log("firebaseDeviceId: " + activatePassword.firebaseDeviceId);

                                SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(activatePassword);
                                String storedFirebaseDeviceIdEncrypted = sharedPreferences.getString(activatePassword.getString(R.string.firebase_device_id), activatePassword.getString(R.string.empty_string));
                                String storedFirebaseDeviceId = CryptoUtilities.decrypt(userSecurityKeyHex, storedFirebaseDeviceIdEncrypted);
                                log("################################ STORED FIREBASE DEVICE ID: " + storedFirebaseDeviceId);

                                if (!activatePassword.firebaseDeviceId.equals(storedFirebaseDeviceId)) {

                                    SharedPreferences.Editor prefEditor = sharedPreferences.edit();
                                    String firebaseDeviceIdEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, activatePassword.firebaseDeviceId);
                                    prefEditor.putString(activatePassword.getString(R.string.firebase_device_id), firebaseDeviceIdEncrypted);
                                    prefEditor.apply();

                                    String userUuidEncrypted = sharedPreferences.getString(activatePassword.getString(R.string.user_uuid_key), activatePassword.getString(R.string.empty_string));
                                    activatePassword.userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, userUuidEncrypted);
                                    log("userUuid: " + activatePassword.userUuid);

                                    String encryptedPrivateKeyHex = sharedPreferences.getString(activatePassword.getString(R.string.crypto_private_key), activatePassword.getString(R.string.empty_string));
                                    log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

                                    activatePassword.privateKey = CryptoUtilities.retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

                                    String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(activatePassword.userUuid, activatePassword.privateKey,
                                            Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

                                    assert paramStrings != null;
                                    String urlParameters = paramStrings[0];
                                    String transferKeyHex = paramStrings[1];

                                    String[] urlStrings = {Constants.RETRIEVE_MOBILE_APP_PROVIDER_TRANSACTION_UUID_URL, urlParameters, transferKeyHex};

                                    /*
                                     * Retrieve a transaction UUID that is signed with the user's private key to verify the transaction.
                                     * In the onPostExecute(...) method of ProcessRetrieveTransactionUuid control is transferred to
                                     * ProcessUpdateFirebaseDeviceId.
                                     */
                                    ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(activatePassword);
                                    processRetrieveTransactionUuid.execute(urlStrings);

                                } else if (activatePassword.firebaseMsgType != null) {

                                    switch (activatePassword.firebaseMsgType) {
                                        case Constants.FIREBASE_MSG_TYPE_CREATE_CREDENTIAL:
                                        case Constants.FIREBASE_MSG_TYPE_SIGN_ON:

                                            Intent credentials = new Intent(activatePassword, Credentials.class);
                                            activatePassword.startActivity(credentials);

                                            break;
                                        case Constants.FIREBASE_MSG_TYPE_CONFIRM_FUNDS_TRANSFER:

                                            Intent confirmFunds = new Intent(activatePassword, ConfirmFunds.class);
                                            activatePassword.startActivity(confirmFunds);

                                            break;
                                        case Constants.FIREBASE_MSG_TYPE_SIGN_DISTRIBUTED_LEDGER:

                                            Intent signature = new Intent(activatePassword, Signature.class);
                                            activatePassword.startActivity(signature);

                                            break;
                                    }

                                } else {

                                    if (!activatePassword.receiveFunds) {
                                        Intent credentials = new Intent(activatePassword, Credentials.class);
                                        activatePassword.startActivity(credentials);
                                    } else {
                                        Intent receiveFunds = new Intent(activatePassword, ReceiveFunds.class);
                                        activatePassword.startActivity(receiveFunds);
                                    }
                                }
                            }
                        });

            } else {

                activatePassword.message.setVisibility(TextView.VISIBLE);
                activatePassword.message.setText(result);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessRetrieveTransactionUuid extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<ActivatePassword> activityReference;

        // only retain a weak reference to the activity
        ProcessRetrieveTransactionUuid(ActivatePassword context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            ActivatePassword activatePassword = activityReference.get();

            if (!activatePassword.isNetworkAvailable()) {
                return activatePassword.getString(R.string.network_unavailable);
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

                    String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, activatePassword);
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

            ActivatePassword activatePassword = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            activatePassword.progressDialog = new ProgressDialog(activatePassword);
            activatePassword.progressDialog.setCancelable(true);
            activatePassword.progressDialog.setTitle(activatePassword.getString(R.string.app_name));
            activatePassword.progressDialog.setMessage(activatePassword.getString(R.string.retrieving_transaction_uuid));
            activatePassword.progressDialog.setIndeterminate(false);
            activatePassword.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            activatePassword.progressDialog.setProgress(0);
            activatePassword.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String transactionUuid) {

            ActivatePassword activatePassword = activityReference.get();

            log("RESULT::" + transactionUuid + "::");

            activatePassword.progressDialog.dismiss();

            // --------------------------------------------------------------------------------------------------------------

            String transferData = Constants.USER_UUID + "=" + activatePassword.userUuid + "&"
                    + Constants.FIRE_BASE_DEVICE_ID + "=" + activatePassword.firebaseDeviceId + "&"
                    + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                    + Constants.TRANSACTION_UUID_SIGNED + "="
                    + CryptoUtilities.generateSignedHex(transactionUuid, activatePassword.privateKey) + "&";

            String[] paramStrings = CryptoUtilities.generateParams_UpdateFirebaseDeviceId(transferData,
                    Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

            assert paramStrings != null;
            String urlParameters = paramStrings[0];
            String transferKeyHex = paramStrings[1];

            String[] urlStrings = {Constants.UPDATE_FIREBASE_DEVICE_ID_URL, urlParameters, transferKeyHex};

            ProcessUpdateFirebaseDeviceId processUpdateFirebaseDeviceId = new ProcessUpdateFirebaseDeviceId(activatePassword);
            processUpdateFirebaseDeviceId.execute(urlStrings);
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessUpdateFirebaseDeviceId extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<ActivatePassword> activityReference;

        // only retain a weak reference to the activity
        ProcessUpdateFirebaseDeviceId(ActivatePassword context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            ActivatePassword activatePassword = activityReference.get();

            if (!activatePassword.isNetworkAvailable()) {
                return activatePassword.getString(R.string.network_unavailable);
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

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, activatePassword);

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

            ActivatePassword activatePassword = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            activatePassword.progressDialog = new ProgressDialog(activatePassword);
            activatePassword.progressDialog.setCancelable(false);
            activatePassword.progressDialog.setTitle(activatePassword.getString(R.string.app_name));
            activatePassword.progressDialog.setMessage(activatePassword.getString(R.string.updating));
            activatePassword.progressDialog.setIndeterminate(false);
            activatePassword.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            activatePassword.progressDialog.setProgress(0);
            activatePassword.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            ActivatePassword activatePassword = activityReference.get();

            log("RESULT::" + result + "::");

            activatePassword.progressDialog.dismiss();

            if (result == null) {
                result = activatePassword.getString(R.string.problem_with_authentication_server);
            }

            if (result.equals(Constants.FIRE_BASE_DEVICE_ID_UPDATED)) {

                Intent credentials = new Intent(activatePassword, Credentials.class);
                activatePassword.startActivity(credentials);

            } else {

                activatePassword.message.setVisibility(TextView.VISIBLE);
                activatePassword.message.setText(result);
            }
        }
    }
}







