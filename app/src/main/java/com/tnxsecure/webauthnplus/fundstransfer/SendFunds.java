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

package com.tnxsecure.webauthnplus.fundstransfer;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.content.ContextCompat;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import com.tnxsecure.webauthnplus.AboutTnx;
import com.tnxsecure.webauthnplus.ActivatePassword;
import com.tnxsecure.webauthnplus.ActivityBase;
import com.tnxsecure.webauthnplus.Credentials;
import com.tnxsecure.webauthnplus.DataBaseManager;
import com.tnxsecure.webauthnplus.Profile;
import com.tnxsecure.webauthnplus.R;
import com.tnxsecure.webauthnplus.WebAuthnPlus;
import com.tnxsecure.webauthnplus.util.Constants;
import com.tnxsecure.webauthnplus.util.CryptoUtilities;
import com.tnxsecure.webauthnplus.util.NumberTextWatcher;
import com.tnxsecure.webauthnplus.util.Utilities;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.text.NumberFormat;
import java.util.Locale;

import static com.tnxsecure.webauthnplus.util.Constants.FUNDS_SENT;
import static com.tnxsecure.webauthnplus.util.Constants.SMS_BASE_URL;

public class SendFunds extends ActivityBase implements OnClickListener {

  private String userSecurityKeyHex;
  private PrivateKey privateKey;
  private EditText transferAmountEditText;
  private String credentialType;
  private String credentialProviderUuid;
  private String retrieveTransactionUuidUrl;
  private String sendFundsUrl;
  private String publicKeyUuid;
  private String publicKeyHex;
  private String userUuid;
  private boolean initiateSendFundsFlag;
  private ProgressDialog progressDialog;

  private String jsonCredential;
  private String senderName;
  private String recipientName;
  private String recipientPhoneNumber;
  private String recipientEmail;
  private String transferAmmountString;
  private String fundsTransferUuid;

  private TextView messageOne;
  private Button sendButton;
  private Button cancelButton;
  private Boolean fundsSent = false;

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onCreate(Bundle savedInstanceState) {

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_send_funds);

    // ----------------------------------------------------------------------------------------------------------------

    ImageView imageView = findViewById(R.id.image_credential_icon);

    userSecurityKeyHex = ((WebAuthnPlus) getApplication()).getUserSecurityKeyHex();
    log("######## userSecurityKeyHex: " + userSecurityKeyHex);

    SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

    String encryptedPrivateKeyHex = sharedPreferences.getString(this.getString(R.string.crypto_private_key), this.getString(R.string.empty_string));
    log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

    privateKey = CryptoUtilities.retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

    String credentialType = ((WebAuthnPlus) getApplication()).getSenderCredentialType();
    log("credentialType: " + credentialType);

    DataBaseManager dataBaseManager = null;

    try {
      dataBaseManager = new DataBaseManager(this);

      Cursor cursor = dataBaseManager.retrieveCredentialByCredentialType(credentialType);

      boolean hasResults = cursor.moveToFirst();
      log("hasResults: " + hasResults);

      byte[] credentialIconByteArray = cursor.getBlob(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_ICON));

      if (credentialIconByteArray != null && credentialIconByteArray.length > 1) {

        float scale = getResources().getDisplayMetrics().density;
        int iconWidth = (int) (scale * 41);
        int iconHeight = (int) (scale * 27);

        ByteArrayInputStream imageStream = new ByteArrayInputStream(credentialIconByteArray);
        Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
        Bitmap credentialIconBitMapScaled = Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

        imageView.setImageBitmap(credentialIconBitMapScaled);
      }

      String providerName = cursor.getString(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_PROVIDER_NAME));
      TextView providerNameView = findViewById(R.id.provider_name);
      providerNameView.setText(providerName);

      String providerUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.DOMAIN_NAME));
      TextView providerUrlView = findViewById(R.id.provider_url);
      providerUrlView.setText(providerUrl);

      String displayName = cursor.getString(cursor.getColumnIndex(DataBaseManager.DISPLAY_NAME));
      TextView displayNameView = findViewById(R.id.display_name);
      displayNameView.setText(displayName);

    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      if (dataBaseManager != null) {
        dataBaseManager.close();
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    recipientName = ((WebAuthnPlus) getApplication()).getRecipientDsplayName();
    log("recipientName: " + recipientName);
    TextView recipientNameView = findViewById(R.id.recipient_name);
    recipientNameView.setText(recipientName);

    recipientPhoneNumber = ((WebAuthnPlus) getApplication()).getRecipientPhoneNumber();
    log("recipientPhoneNumber: " + recipientPhoneNumber);
    TextView recipientPhoneNumberView = findViewById(R.id.recipient_phone_number);
    recipientPhoneNumberView.setText(recipientPhoneNumber);

    recipientEmail = ((WebAuthnPlus) getApplication()).getRecipientEmailAddress();
    log("recipientEmail: " + recipientEmail);
    TextView recipientEmailView = findViewById(R.id.recipient_email);
    recipientEmailView.setText(recipientEmail);

    // ----------------------------------------------------------------------------------------------------------------

    double testAccountBalance = Math.random();
    testAccountBalance *= 1000;

    String testAccountBalanceString = NumberFormat.getCurrencyInstance(new Locale("en", "US")).format(testAccountBalance);

    TextView accountBalanceView = findViewById(R.id.account_balance);
    accountBalanceView.setText(testAccountBalanceString);

    // ----------------------------------------------------------------------------------------------------------------

    transferAmountEditText = findViewById(R.id.transfer_amount);
    transferAmountEditText.addTextChangedListener(new NumberTextWatcher(transferAmountEditText));
    transferAmountEditText.requestFocus();

    sendButton = findViewById(R.id.send_button);
    sendButton.setOnClickListener(this);

    cancelButton = findViewById(R.id.cancel_button);
    cancelButton.setOnClickListener(this);

    InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
    if (inputMethodManager != null) {
      inputMethodManager.toggleSoftInput(InputMethodManager.SHOW_FORCED, 0);
    }

    this.messageOne = findViewById(R.id.message_one);
    this.messageOne.setVisibility(TextView.GONE);
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

    InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
    if (inputMethodManager != null) {
      inputMethodManager.hideSoftInputFromWindow(transferAmountEditText.getWindowToken(), 0);
    }

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

    InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
    if (inputMethodManager != null) {
      inputMethodManager.hideSoftInputFromWindow(transferAmountEditText.getWindowToken(), 0);
    }

    if (!checkMaxIdleTimeExceeded()) {

      /*
       * There are two buttons:  Send and Clear
       */
      switch (view.getId()) {

        case R.id.send_button:

          if (!fundsSent) {

            fundsSent = true;

            transferAmmountString = transferAmountEditText.getText().toString();
            log("transferAmmountString: " + transferAmmountString);

            /*
             * The credential type was saved in the onListItemClick(...) method in the Credentials activity.
             */
            credentialType = ((WebAuthnPlus) getApplication()).getSenderCredentialType();
            log("credentialType: " + credentialType);

            DataBaseManager dataBaseManager = new DataBaseManager(this);

            try {
              Cursor cursor = dataBaseManager.retrieveCredentialByCredentialType(credentialType);

              boolean hasResults = cursor.moveToFirst();
              log("hasResults: " + hasResults);

              credentialProviderUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_PROVIDER_UUID));
              log("credentialProviderUuid: " + credentialProviderUuid);

              retrieveTransactionUuidUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.RETRIEVE_TRANSACTION_UUID_URL));
              log("retrieveTransactionUuidUrl: " + retrieveTransactionUuidUrl);

              sendFundsUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.SEND_FUNDS_URL));
              log("sendFundsUrl: " + sendFundsUrl);

              publicKeyUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY_UUID));
              log("publicKeyUuid: " + publicKeyUuid);

              publicKeyHex = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY));
              log("publicKeyHex: " + publicKeyHex);

              String encryptedUserUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.ENCRYPTED_USER_UUID));
              userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedUserUuid);
              log("userUuid: " + userUuid);

              String encryptedJsonCredential = cursor.getString(cursor.getColumnIndex(DataBaseManager.ENCRYPTED_JSON_CREDENTIAL));
              jsonCredential = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedJsonCredential);
              log("jsonCredential: " + jsonCredential);

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
            initiateSendFundsFlag = true;

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

  void sendSmsMessage() {

    String phoneNumberSms = recipientPhoneNumber.replace("-", "");
    phoneNumberSms = phoneNumberSms.replace("(", "");
    phoneNumberSms = phoneNumberSms.replace(")", "");

    String smsMessage = FUNDS_SENT + SMS_BASE_URL + Constants.SENDER + "=" + credentialProviderUuid + "&" + Constants.REFERENCE + "=" + fundsTransferUuid + "&";
    log("smsMessage: " + smsMessage.length() + " " + smsMessage);

    Uri uri = Uri.parse("smsto:" + phoneNumberSms);
    Intent intent = new Intent(Intent.ACTION_SENDTO, uri);
    intent.putExtra("sms_body", smsMessage);
    startActivity(intent);
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessRetrieveTransactionUuid extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<SendFunds> activityReference;

    // only retain a weak reference to the activity
    ProcessRetrieveTransactionUuid(SendFunds context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      SendFunds sendFunds = activityReference.get();

      if (!sendFunds.isNetworkAvailable()) {
        return sendFunds.getString(R.string.network_unavailable);
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

          String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, sendFunds);
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

      SendFunds sendFunds = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      sendFunds.progressDialog = new ProgressDialog(sendFunds);
      sendFunds.progressDialog.setCancelable(true);
      sendFunds.progressDialog.setTitle(sendFunds.getString(R.string.app_name));
      sendFunds.progressDialog.setMessage(sendFunds.getString(R.string.retrieving_transaction_uuid));
      sendFunds.progressDialog.setIndeterminate(false);
      sendFunds.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      sendFunds.progressDialog.setProgress(0);
      sendFunds.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String transactionUuid) {

      SendFunds sendFunds = activityReference.get();

      log("RESULT::" + transactionUuid + "::");

      sendFunds.progressDialog.dismiss();

      // --------------------------------------------------------------------------------------------------------------

      if (sendFunds.initiateSendFundsFlag) {

        sendFunds.initiateSendFundsFlag = false;

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(sendFunds);

        String screenNameValueEncrypted = sharedPreferences.getString(sendFunds.getString(R.string.screen_name_key), sendFunds.getString(R.string.empty_string));
        String screenNameValue = CryptoUtilities.decrypt(sendFunds.userSecurityKeyHex, screenNameValueEncrypted);
        log("screenNameValue: " + screenNameValue);

        String firstNameValueEncrypted = sharedPreferences.getString(sendFunds.getString(R.string.first_name_key), sendFunds.getString(R.string.empty_string));
        String firstNameValue = CryptoUtilities.decrypt(sendFunds.userSecurityKeyHex, firstNameValueEncrypted);
        log("firstNameValue: " + firstNameValue);

        String lastNameValueEncrypted = sharedPreferences.getString(sendFunds.getString(R.string.last_name_key), sendFunds.getString(R.string.empty_string));
        String lastNameValue = CryptoUtilities.decrypt(sendFunds.userSecurityKeyHex, lastNameValueEncrypted);
        log("lastNameValue: " + lastNameValue);

        String emailValueEncrypted = sharedPreferences.getString(sendFunds.getString(R.string.email_key), sendFunds.getString(R.string.empty_string));
        String emailValue = CryptoUtilities.decrypt(sendFunds.userSecurityKeyHex, emailValueEncrypted);
        log("emailValue: " + emailValue);

        String phoneValueEncrypted = sharedPreferences.getString(sendFunds.getString(R.string.phone_key), sendFunds.getString(R.string.empty_string));
        String phoneValue = CryptoUtilities.decrypt(sendFunds.userSecurityKeyHex, phoneValueEncrypted);
        log("phoneValue: " + phoneValue);

        if (phoneValue == null || phoneValue.length() == 0) {
          phoneValue = sendFunds.getString(R.string.phone_not_in_profile);
        }

        if(firstNameValue == null || firstNameValue.length() == 0 || lastNameValue == null || lastNameValue.length() == 0) {
          sendFunds.senderName = screenNameValue;
        } else {
          sendFunds.senderName = firstNameValue + " " + lastNameValue;
        }

        // ----------------------------------------------------------------------------------------------------------------

        sendFunds.fundsTransferUuid = CryptoUtilities.generateUuidPure();

        String jsonFundsTransfer = "\"fundsTransfer\":[{"
                                 + "\n"
                                 + "\n\"" + Constants.TIMESTAMP + "\":\"" + Utilities.generateIsoTimestamp(System.currentTimeMillis()) + "\", "
                                 + "\n\"" + Constants.TRANSACTION_UUID + "\":\"" + transactionUuid + "\", "
                                 + "\n"
                                 + "\n\"" + Constants.FUNDS_TRANSFER_UUID + "\":\"" + sendFunds.fundsTransferUuid + "\","
                                 + "\n\"" + Constants.TRANSFER_AMOUNT + "\":\"" + sendFunds.transferAmmountString + "\", "
                                 + "\n"
                                 + "\n\"" + Constants.SENDER_DATA + "\":{["
                                 + "\n\"" + Constants.SENDER_NAME + "\":\"" + sendFunds.senderName + "\", "
                                 + "\n\"" + Constants.SENDER_EMAIL + "\":\"" + emailValue + "\", "
                                 + "\n\"" + Constants.SENDER_PHONE_NUMBER + "\":\"" + phoneValue + "\", "
                                 + "\n}]"
                                 + "\n"
                                 + "\n" + sendFunds.jsonCredential
                                 + "\n"
                                 + "\n\"" + Constants.RECIPIENT_DATA + "\":{["
                                 + "\n\"" + Constants.RECIPIENT_NAME + "\":\"" + sendFunds.recipientName + "\", "
                                 + "\n\"" + Constants.RECIPIENT_EMAIL + "\":\"" + sendFunds.recipientEmail + "\", "
                                 + "\n\"" + Constants.RECIPIENT_PHONE_NUMBER + "\":\"" + sendFunds.recipientPhoneNumber + "\", "
                                 + "\n}]"
                                 + "\n"
                                 + "\n\"" + Constants.SENDER_SECURE_HASH_ALGORITHM + "\":\"" + CryptoUtilities.SECURE_HASH_ALGORITHM + "\", "
                                 + "\n\"" + Constants.SENDER_SIGNATURE_ALGORITHM + "\":\"" + CryptoUtilities.SIGNATURE_ALGORITHM + "\", ";

        String senderHash = CryptoUtilities.digest(jsonFundsTransfer);
        log("senderHash::" + senderHash + "::");

        assert senderHash != null;
        String senderSignedHash = CryptoUtilities.generateSignedHex(senderHash, sendFunds.privateKey);
        log("senderSignedHash::" + senderSignedHash + "::");

        jsonFundsTransfer += "\n\"" + Constants.SENDER_HASH + "\":\"" + senderHash + "\", "
                           + "\n\"" + Constants.SENDER_SIGNED_HASH + "\":\"" + senderSignedHash + "\", "
                           + "\n}]";

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

        String transferData = Constants.CREDENTIAL_TYPE + "=" + sendFunds.credentialType + "&"
                + Constants.USER_UUID + "=" + sendFunds.userUuid + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, sendFunds.privateKey) + "&"
                + Constants.JSON_FUNDS_TRANSFER + "=" + jsonFundsTransfer + "&";

        String[] paramStrings = CryptoUtilities.generateParams_SendFunds(transferData, sendFunds.publicKeyUuid, sendFunds.publicKeyHex);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {sendFunds.sendFundsUrl, urlParameters, transferKeyHex};

        ProcessSendFunds processSendFunds = new ProcessSendFunds(sendFunds);
        processSendFunds.execute(urlStrings);
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessSendFunds extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<SendFunds> activityReference;

    // only retain a weak reference to the activity
    ProcessSendFunds(SendFunds context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      SendFunds sendFunds = activityReference.get();

      if (!sendFunds.isNetworkAvailable()) {
        return sendFunds.getString(R.string.network_unavailable);
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

          log("response.toString(): " + response.toString());

          bufferedReader.close();

          return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, sendFunds);

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

      SendFunds sendFunds = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      sendFunds.progressDialog = new ProgressDialog(sendFunds);
      sendFunds.progressDialog.setCancelable(true);
      sendFunds.progressDialog.setTitle(sendFunds.getString(R.string.app_name));
      sendFunds.progressDialog.setMessage(sendFunds.getString(R.string.sending_funds));
      sendFunds.progressDialog.setIndeterminate(false);
      sendFunds.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      sendFunds.progressDialog.setProgress(0);
      sendFunds.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      log("RESULT::" + result + "::");

      SendFunds sendFunds = activityReference.get();

      sendFunds.progressDialog.dismiss();

      if (result.equals(Constants.FUNDS_TRANSFER_INITIALIZED)) {
        sendFunds.sendSmsMessage();
      }

      // ---------------------------------------------------------------------------

      sendFunds.messageOne.setVisibility(TextView.VISIBLE);
      sendFunds.messageOne.setText(result);
      sendFunds.sendButton.setBackground(ContextCompat.getDrawable(sendFunds, R.drawable.button_gradient2));
      sendFunds.cancelButton.setText(R.string.clear);
    }
  }
}



















