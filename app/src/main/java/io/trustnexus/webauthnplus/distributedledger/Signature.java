/*
 * (c) Copyright 2021 ~ Trust Nexus, Inc.
 * All technologies described here in are "Patent Pending".
 * License information:  http://www.trustnexus.io/license.htm
 *
 * AS LONG AS THIS NOTICE IS MAINTAINED THE LICENSE PERMITS REDISTRIBUTION OR RE-POSTING
 * OF THIS SOURCE CODE TO A PUBLIC REPOSITORY (WITH OR WITHOUT MODIFICATIONS)!
 *
 * Report License Violations:  trustnexus.io@austin.rr.com
 */

package io.trustnexus.webauthnplus.distributedledger;

import android.app.NotificationManager;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;

import io.trustnexus.webauthnplus.AboutTnx;
import io.trustnexus.webauthnplus.ActivatePassword;
import io.trustnexus.webauthnplus.Contacts;
import io.trustnexus.webauthnplus.DataBaseManager;
import io.trustnexus.webauthnplus.Profile;
import io.trustnexus.webauthnplus.util.Constants;
import io.trustnexus.webauthnplus.util.CryptoUtilities;
import io.trustnexus.webauthnplus.util.Utilities;
import io.trustnexus.webauthnplus.ImageCursorAdapterCredentials;
import io.trustnexus.webauthnplus.ListActivityBase;

import io.trustnexus.webauthnplus.R;
import io.trustnexus.webauthnplus.WebAuthnPlus;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Signature extends ListActivityBase implements View.OnClickListener {

  private SharedPreferences sharedPreferences;
  private String userSecurityKeyHex;
  private PrivateKey privateKey;

  private TextView credentialProviderName;
  private TextView urlAddress;
  private TextView authenticationCodeLabel;
  private TextView authenticationCode;

  private TextView messageZero;
  private ImageView credentialIcon;
  private Button signatureButton;
  private Button clearButton;

  private TextView messageOne;
  private TextView verificationCodeLabel;
  private TextView verificationCode;
  private TextView scrollMessage;
  private View scrollMessageBottom;
  private TextView sendFundsMessage;
  private View sendFundsMessageBottom;

  private ImageCursorAdapterCredentials imageCursorAdapterCredentials;
  public static String[] FROM_CREDENTIALS = {DataBaseManager.CREDENTIAL_PROVIDER_NAME, DataBaseManager.DOMAIN_NAME, DataBaseManager.DISPLAY_NAME};
  private static int[] TO_CREDENTIALS = {R.id.provider_name, R.id.provider_url, R.id.display_name};

  private String credentialType;
  private String credentialUuid;
  private String verificationCodeValue;
  private String userUuid;
  private String retrieveTransactionUuidUrl;
  private String retrieveUnsignedDistributedLedgerUrl;
  private String returnSignedDistributedLedgerUrl;
  private String publicKeyUuid;
  private String publicKeyHex;

  private boolean processRetrieveUnsignedDistributedLedger;
  private boolean processReturnSignedDistributedLedger;

  private String requestType;
  private String sessionUuid;
  private String distributedLedger;

  private DataBaseManager dataBaseManager;
  private ProgressDialog progressDialog;

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onCreate(Bundle savedInstanceState) {

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_credentials);

    // ----------------------------------------------------------------------------------------------------------------

    userSecurityKeyHex = ((WebAuthnPlus)getApplication()).getUserSecurityKeyHex();
    log("######## userSecurityKeyHex: " + userSecurityKeyHex);

    sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

    String encryptedPrivateKeyHex = sharedPreferences.getString(this.getString(R.string.crypto_private_key), this.getString(R.string.empty_string));
    log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

    privateKey = CryptoUtilities.retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

    // ----------------------------------------------------------------------------------------------------------------

    credentialIcon = findViewById(R.id.credential_icon);
    credentialIcon.setVisibility(ImageView.GONE);

    this.credentialProviderName = findViewById(R.id.credential_provider_name);
    this.credentialProviderName.setVisibility(TextView.GONE);

    this.urlAddress = findViewById(R.id.url_address);
    this.urlAddress.setVisibility(TextView.GONE);

    this.authenticationCodeLabel = findViewById(R.id.authentication_code_label);
    this.authenticationCodeLabel.setVisibility(TextView.GONE);
    this.authenticationCode = findViewById(R.id.authentication_code);
    this.authenticationCode.setVisibility(TextView.GONE);

    this.messageZero = findViewById(R.id.message_zero);

    signatureButton = findViewById(R.id.sign_on_button);
    signatureButton.setOnClickListener(this);

    clearButton = findViewById(R.id.clear_button);
    clearButton.setOnClickListener(this);

    this.messageOne = findViewById(R.id.message_one);
    this.messageOne.setVisibility(TextView.GONE);

    this.verificationCodeLabel = findViewById(R.id.verification_code_label);
    this.verificationCodeLabel.setVisibility(TextView.GONE);
    this.verificationCode = findViewById(R.id.verification_code);
    this.verificationCode.setVisibility(TextView.GONE);

    this.scrollMessage = findViewById(R.id.scroll_message);
    this.scrollMessageBottom = findViewById(R.id.scroll_message_bottom);

    this.sendFundsMessage = findViewById(R.id.send_funds_message);
    this.sendFundsMessageBottom = findViewById(R.id.send_funds_message_bottom);

    // ----------------------------------------------------------------------------------------------------------------

    boolean demoMode = sharedPreferences.getBoolean(getString(R.string.demo_mode_key), true);
    log("demoMode: " + demoMode);

    if (demoMode) {
      dataBaseManager = new DataBaseManager(this);

      try {
        Cursor cursor = dataBaseManager.retrieveCredentialByCredentialProviderName(Constants.TEST_CREDENTIAL_PROVIDER);
        boolean hasResults = cursor.moveToFirst();

        if (!hasResults) {
          dataBaseManager.createTestCredentials(userSecurityKeyHex);
        }

      } finally {
        dataBaseManager.close();
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    /*
     * Populate the scroll list with the credential data.
     */
    displayCredentials();

    // ----------------------------------------------------------------------------------------------------------------

    /*
     * If a Firbase notification comes in and the app is closed or not in focus, the notification is sent to the extras
     * Bundle of the main activity, ActivatePassword.  If a Firbase notification comes in and the app is open, the notification
     * is sent to TnxFirebaseMessagingService.onMessageReceived(...).
     *
     * In both cases the notification values are stored in the Application object "WebAuthnPlus extends Application" and
     * control is transferred to the activity for processing.
     */
    if (((WebAuthnPlus)getApplication()).getFirebaseDataEncryptedHex() != null) {
      processFirebaseMessage();
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  private void processFirebaseMessage() {

    NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
    if (notificationManager != null) {
      notificationManager.cancel(Constants.TNX_NOTIFICATION);
    }

    String firebaseDataEncryptedHex = ((WebAuthnPlus)getApplication()).getFirebaseDataEncryptedHex();
    log("################################ firebaseDataEncryptedHex: " + firebaseDataEncryptedHex);
    log("################################ firebaseData length: " + firebaseDataEncryptedHex.length());

    String firebaseDataEncryptedHashedHex = ((WebAuthnPlus)getApplication()).getFirebaseDataEncryptedHashedHex();
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

        String credentialProviderNameValue = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.CREDENTIAL_PROVIDER_NAME);
        log("################################ credentialProviderNameValue: " + credentialProviderNameValue);
        ((WebAuthnPlus)getApplication()).setCredentialProviderName(credentialProviderNameValue);

        String domainName = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.DOMAIN_NAME);
        log("################################ domainName: " + domainName);
        ((WebAuthnPlus)getApplication()).setDomainName(domainName);

        String authenticationCodeMsg = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.AUTHENTICATION_CODE);
        log("################################ authenticationCodeMsg: " + authenticationCodeMsg);
        ((WebAuthnPlus)getApplication()).setAuthenticationCode(authenticationCodeMsg);

        requestType = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.FIREBASE_MSG_TYPE_KEY);
        log("################################ requestType: " + requestType);

        credentialType = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.CREDENTIAL_TYPE);
        log("################################ credentialType: " + credentialType);
        ((WebAuthnPlus)getApplication()).setCreateCredentialType(credentialType);

        credentialUuid = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.CREDENTIAL_UUID);
        log("################################ credentialUuid: " + credentialUuid);
        ((WebAuthnPlus)getApplication()).setCredentialUuid(credentialUuid);

        sessionUuid = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.SESSION_UUID);
        log("################################ sessionUuid: " + sessionUuid);
        ((WebAuthnPlus)getApplication()).setSessionUuid(sessionUuid);

        this.credentialProviderName.setVisibility(TextView.VISIBLE);
        this.credentialProviderName.setText(credentialProviderNameValue);

        urlAddress.setVisibility(TextView.VISIBLE);
        urlAddress.setText(domainName);

        authenticationCodeLabel.setVisibility(TextView.VISIBLE);
        authenticationCode.setVisibility(TextView.VISIBLE);
        authenticationCode.setText(authenticationCodeMsg);

        messageOne.setText(R.string.empty_string);
        messageOne.setVisibility(TextView.GONE);

        verificationCodeLabel.setVisibility(TextView.GONE);
        verificationCode.setVisibility(TextView.GONE);
        verificationCode.setText(R.string.empty_string);

        if (requestType.equals(Constants.FIREBASE_MSG_TYPE_SIGN_DISTRIBUTED_LEDGER)) {

          messageZero.setText(R.string.signature_instructions);

          signatureButton.setBackground(getResources().getDrawable(R.drawable.button_gradient));
          signatureButton.setText(R.string.signature);
          clearButton.setBackground(getResources().getDrawable(R.drawable.button_gradient));

          try {
            Cursor cursor = dataBaseManager.retrieveCredentialByCredentialType(credentialType);

            boolean hasResults = cursor.moveToFirst();
            log("hasResults: " + hasResults);

            if (hasResults) {

              byte[] credentialIconByteArray = cursor.getBlob(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_ICON));

              if (credentialIconByteArray != null && credentialIconByteArray.length > 1) {

                float scale = getResources().getDisplayMetrics().density;
                int iconWidth = (int)(scale*41);
                int iconHeight = (int)(scale*27);

                ByteArrayInputStream imageStream = new ByteArrayInputStream(credentialIconByteArray);
                Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
                Bitmap credentialIconBitMapScaled =   Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

                credentialIcon.setImageBitmap(credentialIconBitMapScaled);

              } else {
                credentialIcon.setImageResource(R.mipmap.app_icon);
              }

              credentialIcon.setVisibility(ImageView.VISIBLE);

            } else {
              messageZero.setText(R.string.problem_retrieving_credential_type);
            }

          } finally {
            dataBaseManager.close();
          }
        }

      } else {
        messageZero.setText(R.string.firebase_message_integrity_compromised);
      }

      ((WebAuthnPlus)getApplication()).setFirebaseDataEncryptedHex(null);
      ((WebAuthnPlus)getApplication()).setFirebaseDataEncryptedHashedHex(null);

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onResume() {
    super.onResume();

    displayCredentials();
  }

  // ------------------------------------------------------------------------------------------------------------------

  /*
   * Displays the credential list from the database.
   */
  private void displayCredentials() {

    try {

      if (dataBaseManager == null) {
        dataBaseManager = new DataBaseManager(this);
      }

      Cursor cursor = dataBaseManager.retrieveCredentials();

      imageCursorAdapterCredentials = new ImageCursorAdapterCredentials(this, R.layout.item_credential, cursor, FROM_CREDENTIALS, TO_CREDENTIALS);
      setListAdapter(imageCursorAdapterCredentials);

      if (cursor.getCount() > 4) {
        scrollMessage.setVisibility(TextView.GONE);
        scrollMessageBottom.setVisibility(TextView.GONE);
      }

      // ----------------------------------------------------------------------------------------------------------------

      cursor = dataBaseManager.retrieveCredentialLikeCredentialType(getString(R.string.credential_type_financial));
      boolean hasResults = cursor.moveToFirst();

      if (hasResults) {
        sendFundsMessage.setVisibility(TextView.VISIBLE);
        sendFundsMessageBottom.setVisibility(TextView.VISIBLE);
      } else {
        sendFundsMessage.setVisibility(TextView.GONE);
        sendFundsMessageBottom.setVisibility(TextView.GONE);
      }

    } finally {
      if (dataBaseManager != null) {
        dataBaseManager.close();
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onClick(View view) {

    if (!checkMaxIdleTimeExceeded()) {

      /*
       * There are two buttons:  Sign On and Clear
       */
      switch (view.getId()) {

        case R.id.sign_on_button:

          if(requestType != null) {

            /*
             * The "Sign On" button is used for credential creation and signing on.
             * The label is changed based on the Firebase message.
             */

            /*
             * The verificationCodeValue is the value created by this application and sent to the web application
             * (encrypted).  The verificationCodeValue is displayed on both the confirmation page of the web application
             * and the confirmation screen of this application.
             */
            verificationCodeValue = Utilities.generateVerificationCode();
            ((WebAuthnPlus) getApplication()).setVerificationCodeValue(verificationCodeValue);
            log("verificationCodeValue: " + verificationCodeValue);

            String userUuidEncrypted = sharedPreferences.getString(getString(R.string.user_uuid_key), getString(R.string.empty_string));
            userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, userUuidEncrypted);
            log("userUuid: " + userUuid);

            // ----------------------------------------------------------------------------------------------------------

            if (requestType.equals(Constants.FIREBASE_MSG_TYPE_SIGN_DISTRIBUTED_LEDGER)) {

              /*
               * The credential type was received in the Firebase message.
               */
              credentialType = ((WebAuthnPlus) getApplication()).getCreateCredentialType();
              log("credentialType: " + credentialType);

              dataBaseManager = new DataBaseManager(this);

              try {
                Cursor cursor = dataBaseManager.retrieveCredentialByCredentialType(credentialType);

                boolean hasResults = cursor.moveToFirst();
                log("hasResults: " + hasResults);

                retrieveTransactionUuidUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.RETRIEVE_TRANSACTION_UUID_URL));
                log("retrieveTransactionUuidUrl: " + retrieveTransactionUuidUrl);

                retrieveUnsignedDistributedLedgerUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL));
                log("retrieveUnsignedDistributedLedgerUrl: " + retrieveUnsignedDistributedLedgerUrl);

                returnSignedDistributedLedgerUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.RETURN_SIGNED_DISTRIBUTED_LEDGER_URL));
                log("returnSignedDistributedLedgerUrl: " + returnSignedDistributedLedgerUrl);

                publicKeyUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY_UUID));
                log("publicKeyUuid: " + publicKeyUuid);

                publicKeyHex = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY));
                log("publicKeyHex: " + publicKeyHex);

                String encryptedUserUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.ENCRYPTED_USER_UUID));
                userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedUserUuid);
                log("userUuid: " + userUuid);

              } catch (Exception e) {
                e.printStackTrace();
              } finally {
                dataBaseManager.close();
              }

              // --------------------------------------------------------------------------------------------------------

              String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey, publicKeyUuid, publicKeyHex);

              assert paramStrings != null;
              String urlParameters = paramStrings[0];
              String transferKeyHex = paramStrings[1];

              String[] urlStrings = {retrieveTransactionUuidUrl, urlParameters, transferKeyHex};

              /*
               * This method makes a call to the web application.  Like almost all methodsthat make a call to the web
               * application a call is first made to get a TransactionUuid (which adds security to the process), then
               * from that inner class control is transferred to another inner class based on a flag.
               */
              processRetrieveUnsignedDistributedLedger = true;

              Signature.ProcessRetrieveTransactionUuid processRetrieveTransactionUuid
                      = new Signature.ProcessRetrieveTransactionUuid(this);
              processRetrieveTransactionUuid.execute(urlStrings);
            }
          }

          break;

        case R.id.clear_button:

          clearDisplay();

          break;

        default:
          break;
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  private void clearDisplay () {

    credentialIcon.setVisibility(ImageView.GONE);

    credentialProviderName.setVisibility(TextView.GONE);
    credentialProviderName.setText(R.string.empty_string);

    urlAddress.setVisibility(TextView.GONE);
    urlAddress.setText(R.string.empty_string);

    authenticationCodeLabel.setVisibility(TextView.GONE);
    authenticationCode.setVisibility(TextView.GONE);
    authenticationCode.setText(R.string.empty_string);

    messageZero.setText(R.string.authentication_message);
    messageZero.setTypeface(null, Typeface.NORMAL);

    messageOne.setText(R.string.empty_string);
    messageOne.setVisibility(TextView.GONE);

    verificationCodeLabel.setVisibility(TextView.GONE);
    verificationCode.setVisibility(TextView.GONE);
    verificationCode.setText(R.string.empty_string);

    float scale = getResources().getDisplayMetrics().density;
    int paddingLeftRight = (int) (20 * scale + 0.5f);
    int paddingTopBottom = (int) (5 * scale + 0.5f);

    signatureButton.setText(R.string.sign_on);
    signatureButton.setPadding(paddingLeftRight, paddingTopBottom, paddingLeftRight, paddingTopBottom);
    signatureButton.setBackground(getResources().getDrawable(R.drawable.button_gradient2));
    signatureButton.setOnClickListener(null);
    clearButton.setBackground(getResources().getDrawable(R.drawable.button_gradient2));
  }

  // ------------------------------------------------------------------------------------------------------------------

  protected void onListItemClick(ListView listView, View view, int position, long id) {

    if (!checkMaxIdleTimeExceeded()) {

      clearDisplay();

      Cursor cursor = (Cursor) imageCursorAdapterCredentials.getItem(position);

      credentialType = cursor.getString(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_TYPE));
      log("credentialType: " + credentialType);

      if (credentialType.contains(".DISPLAY_ONLY")) {
        messageZero.setText(getText(R.string.display_only));
      } else if (credentialType.contains(getString(R.string.credential_type_financial))) {

        ((WebAuthnPlus)getApplication()).setSenderCredentialType(credentialType);

        Intent contacts = new Intent(this, Contacts.class);
        startActivity(contacts);

      } else {
        messageZero.setText(getText(R.string.coming_soon_secure_access));
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {

    boolean result = super.onCreateOptionsMenu(menu);

    MenuInflater menuInflater = getMenuInflater();
    menuInflater.inflate(R.menu.menu_credentials, menu);

    return result;
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {

    boolean result = super.onOptionsItemSelected(item);

    switch (item.getItemId()) {

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

        ((WebAuthnPlus)getApplication()).setExitValues();

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
    private WeakReference<Signature> activityReference;

    // only retain a weak reference to the activity
    ProcessRetrieveTransactionUuid(Signature context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Signature signature = activityReference.get();

      if (!signature.isNetworkAvailable()) {
        return signature.getString(R.string.network_unavailable);
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

          connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));
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

          String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, signature);
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

      Signature signature = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      signature.progressDialog = new ProgressDialog(signature);
      signature.progressDialog.setCancelable(true);
      signature.progressDialog.setTitle(signature.getString(R.string.app_name));
      signature.progressDialog.setMessage(signature.getString(R.string.retrieving_transaction_uuid));
      signature.progressDialog.setIndeterminate(false);
      signature.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      signature.progressDialog.setProgress(0);
      signature.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String transactionUuid) {

      Signature signature = activityReference.get();

      log("RESULT::" + transactionUuid + "::");

      signature.progressDialog.dismiss();

      // --------------------------------------------------------------------------------------------------------------

      if (signature.processRetrieveUnsignedDistributedLedger) {

        signature.processRetrieveUnsignedDistributedLedger = false;

        String transferData = Constants.USER_UUID + "=" + signature.userUuid + "&"
                + Constants.CREDENTIAL_UUID + "=" + signature.credentialUuid + "&"
                + Constants.SESSION_UUID + "=" + signature.sessionUuid + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, signature.privateKey) + "&";

        String[] paramStrings = CryptoUtilities.generateParams_RetrieveUnsignedDistributedLedger(transferData, signature.publicKeyUuid, signature.publicKeyHex);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {signature.retrieveUnsignedDistributedLedgerUrl, urlParameters, transferKeyHex};

        Signature.ProcessRetrieveUnsignedDistributedLedger processRetrieveUnsignedDistributedLedger
                = new Signature.ProcessRetrieveUnsignedDistributedLedger(signature);
        processRetrieveUnsignedDistributedLedger.execute(urlStrings);

      } else if (signature.processReturnSignedDistributedLedger) {

        signature.processReturnSignedDistributedLedger = false;

        int indexOfclosingSymbols = signature.distributedLedger.lastIndexOf("\n}]");
        signature.distributedLedger = signature.distributedLedger.substring(0, indexOfclosingSymbols);

        String distributedLedgerHash = CryptoUtilities.digest(signature.distributedLedger);
        log("distributedLedgerHash::" + distributedLedgerHash + "::");

        String distributedLedgerSignedHash = CryptoUtilities.generateSignedHex(distributedLedgerHash, signature.privateKey);
        log("distributedLedgerSignedHash::" + distributedLedgerSignedHash + "::");

        signature.distributedLedger += "\n\n\"" + Constants.DISTRIBUTED_LEDGER_HASH + "\":\"" + distributedLedgerHash + "\", "
                                       + "\n\n\"" + Constants.DISTRIBUTED_LEDGER_SIGNED_HASH + "\":\"" + distributedLedgerSignedHash + "\", "
                                       + "\n}]\n";

        String transferData = Constants.VERIFICATION_CODE + "=" + signature.verificationCodeValue + "&"
                + Constants.USER_UUID + "=" + signature.userUuid + "&"
                + Constants.CREDENTIAL_UUID + "=" + signature.credentialUuid + "&"
                + Constants.SESSION_UUID + "=" + signature.sessionUuid + "&"
                + Constants.DISTRIBUTED_LEDGER + "=" + signature.distributedLedger + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, signature.privateKey) + "&";

        String[] paramStrings = CryptoUtilities.generateParams_ReturnSignedDistributedLedger(transferData, signature.publicKeyUuid, signature.publicKeyHex);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {signature.returnSignedDistributedLedgerUrl, urlParameters, transferKeyHex};

        Signature.ProcessReturnSignedDistributedLedger processReturnSignedDistributedLedger
                = new Signature.ProcessReturnSignedDistributedLedger(signature);
        processReturnSignedDistributedLedger.execute(urlStrings);
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessRetrieveUnsignedDistributedLedger extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Signature> activityReference;

    // only retain a weak reference to the activity
    ProcessRetrieveUnsignedDistributedLedger(Signature context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Signature signature = activityReference.get();

      if (!signature.isNetworkAvailable()) {
        return signature.getString(R.string.network_unavailable);
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

          connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));
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

          log("response: " + response);

          bufferedReader.close();

          // ----------------------------------------------------------------------------------------------------------

          String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, signature);
          log("responseString: " + responseString);

          if (responseString.equals(signature.getString(R.string.problem_with_authentication_server))) {
            return responseString;
          } else {

            signature.distributedLedger = Utilities.parseNameValuePairs(responseString, Constants.DISTRIBUTED_LEDGER);
            log("distributedLedger::" + signature.distributedLedger + "::");

            responseString = Constants.DISTRIBUTED_LEDGER_DOWNLOADED;
          }

          return responseString;

        } catch (Exception e) {
          e.printStackTrace();
          return signature.getString(R.string.problem_retrieving_credential_provider);
        } finally {
          if (connection != null) {
            connection.disconnect();
          }
        }
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    protected void onPreExecute() {

      Signature signature = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      signature.progressDialog = new ProgressDialog(signature);
      signature.progressDialog.setCancelable(true);
      signature.progressDialog.setTitle(signature.getString(R.string.app_name));
      signature.progressDialog.setMessage(signature.getString(R.string.retrieve_unsigned_distributed_ledger));
      signature.progressDialog.setIndeterminate(false);
      signature.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      signature.progressDialog.setProgress(0);
      signature.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Signature signature = activityReference.get();

      log("RESULT::" + result + "::");

      signature.progressDialog.dismiss();

      // --------------------------------------------------------------------------------------------------------------

      if (result.equals(Constants.DISTRIBUTED_LEDGER_DOWNLOADED)) {

        String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(signature.userUuid, signature.privateKey, signature.publicKeyUuid, signature.publicKeyHex);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {signature.retrieveTransactionUuidUrl, urlParameters, transferKeyHex};

              /*
               * This method makes a call to the web application.  Like almost all methodsthat make a call to the web
               * application a call is first made to get a TransactionUuid (which adds security to the process), then
               * from that inner class control is transferred to another inner class based on a flag.
               */
        signature.processReturnSignedDistributedLedger = true;

        Signature.ProcessRetrieveTransactionUuid processRetrieveTransactionUuid
                = new Signature.ProcessRetrieveTransactionUuid(signature);
        processRetrieveTransactionUuid.execute(urlStrings);

      } else {

        signature.messageZero.setText(result);

        signature.credentialIcon.setVisibility(ImageView.GONE);

        signature.credentialProviderName.setVisibility(TextView.GONE);
        signature.urlAddress.setVisibility(TextView.GONE);

        signature.authenticationCodeLabel.setVisibility(TextView.GONE);
        signature.authenticationCode.setVisibility(TextView.GONE);

        signature.verificationCodeLabel.setVisibility(TextView.GONE);
        signature.verificationCode.setVisibility(TextView.GONE);
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessReturnSignedDistributedLedger extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Signature> activityReference;

    // only retain a weak reference to the activity
    ProcessReturnSignedDistributedLedger(Signature context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Signature signature = activityReference.get();

      if (!signature.isNetworkAvailable()) {
        return signature.getString(R.string.network_unavailable);
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

          connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));
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

          log("response: " + response);

          bufferedReader.close();

          // ----------------------------------------------------------------------------------------------------------

          String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, signature);
          log("responseString: " + responseString);

          return responseString;

        } catch (Exception e) {
          e.printStackTrace();
          return signature.getString(R.string.problem_retrieving_credential_provider);
        } finally {
          if (connection != null) {
            connection.disconnect();
          }
        }
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    protected void onPreExecute() {

      Signature signature = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      signature.progressDialog = new ProgressDialog(signature);
      signature.progressDialog.setCancelable(true);
      signature.progressDialog.setTitle(signature.getString(R.string.app_name));
      signature.progressDialog.setMessage(signature.getString(R.string.return_signed_distributed_ledger));
      signature.progressDialog.setIndeterminate(false);
      signature.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      signature.progressDialog.setProgress(0);
      signature.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Signature signature = activityReference.get();

      log("RESULT::" + result + "::");

      signature.progressDialog.dismiss();

      if (result == null) {
        result = signature.getString(R.string.problem_with_authentication_server);
      }

      signature.messageOne.setVisibility(TextView.VISIBLE);
      signature.messageOne.setText(result);

      signature.credentialIcon.setVisibility(ImageView.GONE);
      signature.credentialProviderName.setVisibility(TextView.GONE);
      signature.urlAddress.setVisibility(TextView.GONE);

      signature.authenticationCodeLabel.setVisibility(TextView.GONE);
      signature. authenticationCode.setVisibility(TextView.GONE);

      signature.signatureButton.setBackground(((WebAuthnPlus) signature.getApplication()).getResources().getDrawable(R.drawable.button_gradient2));
      signature.signatureButton.setOnClickListener(null);

      if (result.equals(Constants.SIGNATURE_SUCCESSFUL)) {

        signature.messageZero.setText(result);

        String screenName = CryptoUtilities.decrypt(signature.userSecurityKeyHex, signature.sharedPreferences.getString( signature.getString(R.string.screen_name_key), signature.getString(R.string.empty_string)));

        signature.messageZero.setVisibility(TextView.VISIBLE);
        String welcomMessage = signature.getString(R.string.thank_you) + " " + screenName.trim();
        signature. messageZero.setText(welcomMessage);
        signature.messageZero.setTypeface(null, Typeface.BOLD);

        signature.verificationCodeLabel.setVisibility(TextView.VISIBLE);
        signature.verificationCode.setVisibility(TextView.VISIBLE);
        signature.verificationCode.setText(((WebAuthnPlus) signature.getApplication()).getVerificationCodeValue());

      } else {

        signature.messageZero.setText(result);

        signature.credentialIcon.setVisibility(ImageView.GONE);

        signature.credentialProviderName.setVisibility(TextView.GONE);
        signature.urlAddress.setVisibility(TextView.GONE);

        signature.authenticationCodeLabel.setVisibility(TextView.GONE);
        signature.authenticationCode.setVisibility(TextView.GONE);

        signature.verificationCodeLabel.setVisibility(TextView.GONE);
        signature.verificationCode.setVisibility(TextView.GONE);
      }
    }
  }
}







