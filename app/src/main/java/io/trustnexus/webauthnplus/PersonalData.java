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

package io.trustnexus.webauthnplus;

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
import android.widget.CheckBox;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import io.trustnexus.webauthnplus.util.Constants;
import io.trustnexus.webauthnplus.util.CryptoUtilities;
import io.trustnexus.webauthnplus.util.Utilities;

import io.trustnexus.webauthnplus.R;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;

public class PersonalData extends ActivityBase implements OnClickListener {

  private String userSecurityKeyHex;
  private PrivateKey privateKey;

  private CheckBox firstNameLastName;
  private CheckBox phoneNumber;
  private CheckBox legalAddress;
  private CheckBox mailingAddress;
  private CheckBox organizationInformation;

  private DataBaseManager dataBaseManager;
  private ProgressDialog progressDialog;

  private String createCredentialUrl;
  private String retrieveTransactionUuidUrl;
  private String credentialProviderUuid;
  private String userUuid;
  private String credentialUuid;
  private String credentialType;
  private String userData;
  private String publicKeyUuid;
  private String publicKeyHex;

  @Override
  public void onCreate(Bundle savedInstanceState) {

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_personal_data);

    ImageView applicationIcon = (ImageView) findViewById(android.R.id.home);
    FrameLayout.LayoutParams applicationIconLayoutParams = (FrameLayout.LayoutParams) applicationIcon.getLayoutParams();
    applicationIconLayoutParams.topMargin = 0;
    applicationIconLayoutParams.bottomMargin = 0;
    applicationIcon.setLayoutParams(applicationIconLayoutParams);

    // ----------------------------------------------------------------------------------------------------------------

    userSecurityKeyHex = ((WebAuthnPlus)getApplication()).getUserSecurityKeyHex();
    log("######## userSecurityKeyHex: " + userSecurityKeyHex);

    SharedPreferences sharedPreferences1 = PreferenceManager.getDefaultSharedPreferences(this);

    String encryptedPrivateKeyHex = sharedPreferences1.getString(this.getString(R.string.crypto_private_key), this.getString(R.string.empty_string));
    log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

    privateKey = CryptoUtilities.retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

    // ----------------------------------------------------------------------------------------------------------------

    float scale = getResources().getDisplayMetrics().density;
    int iconWidth = (int)(scale*41);
    int iconHeight = (int)(scale*27);

    ByteArrayInputStream imageStream = new ByteArrayInputStream(((WebAuthnPlus)getApplication()).getCredentialIconByteArray());
    Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
    Bitmap credentialIconBitMapScaled =   Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

    ImageView credentialIcon = (ImageView) findViewById(R.id.credential_icon);
    credentialIcon.setImageBitmap(credentialIconBitMapScaled);

    TextView credentialProviderName = (TextView) findViewById(R.id.credential_provider_name);
    TextView urlAddress = (TextView) findViewById(R.id.url_address);
    TextView authenticationCode = (TextView) findViewById(R.id.authentication_code);

    this.firstNameLastName = (CheckBox)findViewById(R.id.first_name_last_name);
    this.phoneNumber = (CheckBox)findViewById(R.id.phone_number);
    this.legalAddress = (CheckBox)findViewById(R.id.legal_address);
    this.mailingAddress = (CheckBox)findViewById(R.id.mailing_address);
    this.organizationInformation = (CheckBox)findViewById(R.id.organization_information);

    Button personalDataButton = (Button) findViewById(R.id.personal_data_button);
    personalDataButton.setOnClickListener(this);

    // ----------------------------------------------------------------------------------------------------------------

    authenticationCode.setText(((WebAuthnPlus)getApplication()).getAuthenticationCode());

    credentialType = ((WebAuthnPlus)getApplication()).getCreateCredentialType();
    log("credentialType: " + credentialType);

    dataBaseManager = new DataBaseManager(this);

    try {
      Cursor cursor = dataBaseManager.retrieveCredentialByCredentialType(credentialType);

      boolean hasResults = cursor.moveToFirst();
      log("hasResults: " + hasResults);

      credentialProviderUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_PROVIDER_UUID));
      log("credentialProviderUuid: " + credentialProviderUuid);

      String encryptedCredentialUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.ENCRYPTED_CREDENTIAL_UUID));
      credentialUuid = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedCredentialUuid);
      log("credentialUuid: " + credentialUuid);

      String credentialProviderNameValue = cursor.getString(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_PROVIDER_NAME));
      credentialProviderName.setText(credentialProviderNameValue);
      log("credentialProviderNameValue: " + credentialProviderNameValue);

      String urlAddressValue = cursor.getString(cursor.getColumnIndex(DataBaseManager.DOMAIN_NAME));
      urlAddress.setText(urlAddressValue);
      log("providerUrlValue: " + urlAddressValue);

      createCredentialUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.CREATE_CREDENTIAL_URL));
      log("createCredentialUrl: " + createCredentialUrl);

      retrieveTransactionUuidUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.RETRIEVE_TRANSACTION_UUID_URL));
      log("retrieveTransactionUuidUrl: " + retrieveTransactionUuidUrl);

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
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onClick(View arg0) {

    SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

    String verificationCode = Utilities.generateVerificationCode();
    ((WebAuthnPlus)getApplication()).setVerificationCodeValue(verificationCode);

    String encryptedPublicKeyHex = sharedPreferences.getString(this.getString(R.string.crypto_public_key), this.getString(R.string.empty_string));
    log("encryptedPublicKeyHex: " + encryptedPublicKeyHex);

    String publicKeyHex = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedPublicKeyHex);

    userData = Constants.CREDENTIAL_UUID + "=" + credentialUuid + "&"
             + Constants.CREDENTIAL_TYPE + "=" + credentialType + "&"
             + Constants.CREDENTIAL_PROVIDER_UUID + "=" + credentialProviderUuid + "&"
             + Constants.VERIFICATION_CODE + "=" + verificationCode + "&"

             + Constants.AUTHENTICATION_CODE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.authentication_code_key), getString(R.string.empty_string))) + "&"
             + Constants.SCREEN_NAME + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.screen_name_key), getString(R.string.empty_string))) + "&"
             + Constants.EMAIL + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.email_key), getString(R.string.empty_string))) + "&"
             + Constants.USER_UUID + "=" + userUuid + "&"
             + Constants.PUBLIC_KEY_HEX + "=" + publicKeyHex + "&";

    if (firstNameLastName.isChecked()) {
      userData += Constants.FIRST_NAME + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.first_name_key), getString(R.string.empty_string))) + "&"
              + Constants.LAST_NAME + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.last_name_key), getString(R.string.empty_string))) + "&";
    }

    // ----------------------------------------------------------------------------------------------------------------

    if (phoneNumber.isChecked()) {
      userData += Constants.PHONE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.phone_key), getString(R.string.empty_string))) + "&";
    }

    // ----------------------------------------------------------------------------------------------------------------

    String addressType = null;

    boolean sameAddressValue = sharedPreferences.getBoolean(getString(R.string.same_address_key), false);

    if (sameAddressValue) {
      addressType = getString(R.string.mail_type_legal_and_mailing_key);
    }

    // ----------------------------------------------------------------------------------------------------------------

    if (legalAddress.isChecked()) {

      if (addressType == null) {
        addressType = getString(R.string.mail_type_legal_key);
      }

      userData += Constants.LEGAL_ADDRESS_LINE_ONE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.legal_address_line_one_key), getString(R.string.empty_string))) + "&"
                + Constants.LEGAL_ADDRESS_LINE_TWO + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.legal_address_line_two_key), getString(R.string.empty_string))) + "&"
                + Constants.LEGAL_ADDRESS_CITY + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.legal_address_city_key), getString(R.string.empty_string))) + "&"
                + Constants.LEGAL_ADDRESS_STATE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.legal_address_state_key), getString(R.string.empty_string))) + "&"
                + Constants.LEGAL_ADDRESS_POSTAL_CODE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.legal_address_postal_code_key), getString(R.string.empty_string))) + "&"
                + Constants.LEGAL_ADDRESS_COUNTRY + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.legal_address_country_key), getString(R.string.empty_string))) + "&"
                + Constants.ADDRESS_TYPE + "=" + addressType + "&";
    }

    // ----------------------------------------------------------------------------------------------------------------

    if (mailingAddress.isChecked() && !sameAddressValue) {

      if (addressType == null) {
        addressType = getString(R.string.mail_type_mailing_key);
      }

      userData += Constants.MAILING_ADDRESS_LINE_ONE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.mailing_address_line_one_key), getString(R.string.empty_string))) + "&"
                + Constants.MAILING_ADDRESS_LINE_TWO + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.mailing_address_line_two_key), getString(R.string.empty_string))) + "&"
                + Constants.MAILING_ADDRESS_CITY + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.mailing_address_city_key), getString(R.string.empty_string))) + "&"
                + Constants.MAILING_ADDRESS_STATE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.mailing_address_state_key), getString(R.string.empty_string))) + "&"
                + Constants.MAILING_ADDRESS_POSTAL_CODE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.mailing_address_postal_code_key), getString(R.string.empty_string))) + "&"
                + Constants.MAILING_ADDRESS_COUNTRY + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.mailing_address_country_key), getString(R.string.empty_string))) + "&"
                + Constants.ADDRESS_TYPE + "=" + addressType + "&";
    }

    // ----------------------------------------------------------------------------------------------------------------

    if (organizationInformation.isChecked()) {

      userData += Constants.ORGANIZATION_NAME + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_name_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_URL + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_url_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_TITLE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_title_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_PHONE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_phone_key), getString(R.string.empty_string))) + "&";

      userData += Constants.ORGANIZATION_ADDRESS_LINE_ONE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_address_line_one_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_ADDRESS_LINE_TWO + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_address_line_two_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_ADDRESS_CITY + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_address_city_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_ADDRESS_STATE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_address_state_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_ADDRESS_POSTAL_CODE + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_address_postal_code_key), getString(R.string.empty_string))) + "&"
                + Constants.ORGANIZATION_ADDRESS_COUNTRY + "=" + CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.organization_address_country_key), getString(R.string.empty_string))) + "&";
    }

    // ----------------------------------------------------------------------------------------------------------------

    String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

    assert paramStrings != null;
    String urlParameters = paramStrings[0];
    String transferKeyHex = paramStrings[1];

    String[] urlStrings = {retrieveTransactionUuidUrl, urlParameters, transferKeyHex};

    /*
     * Retrieve a transaction UUID is be signed with the user's private key to verify the transaction.
     *
     * In the onPostExecute(...) method of ProcessRetrieveTransactionUuid control is transferred to
     * ProcessCreateCredential.
     */
    ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
    processRetrieveTransactionUuid.execute(urlStrings);
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {

    boolean result = super.onCreateOptionsMenu(menu);

    MenuInflater menuInflater = getMenuInflater();
    menuInflater.inflate(R.menu.options_menu, menu);

    return result;
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {

    boolean result = super.onOptionsItemSelected(item);

    switch (item.getItemId()) {

      case R.id.credentials_menu:

        if (!checkMaxIdleTimeExceeded()) {
          Intent credentials = new Intent(this, Credentials.class);
          startActivity(credentials);
        }

        break;

      case R.id.profile_menu:

        if (!checkMaxIdleTimeExceeded()) {
          Intent profile = new Intent(this, Profile.class);
          startActivity(profile);
        }

        break;

      case R.id.exit_menu:

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
    private WeakReference<PersonalData> activityReference;

    // only retain a weak reference to the activity
    ProcessRetrieveTransactionUuid(PersonalData context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      PersonalData personalData = activityReference.get();

      if (!personalData.isNetworkAvailable()) {
        return personalData.getString(R.string.network_unavailable);
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

          String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, personalData);
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

      PersonalData personalData = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      personalData.progressDialog = new ProgressDialog(personalData);
      personalData.progressDialog.setCancelable(true);
      personalData.progressDialog.setTitle(personalData.getString(R.string.app_name));
      personalData.progressDialog.setMessage(personalData.getString(R.string.retrieving_transaction_uuid));
      personalData.progressDialog.setIndeterminate(false);
      personalData.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      personalData.progressDialog.setProgress(0);
      personalData.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String transactionUuid) {

      PersonalData personalData = activityReference.get();

      log("RESULT::" + transactionUuid + "::");

      personalData.progressDialog.dismiss();

      personalData.userData += Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
               + Constants.TRANSACTION_UUID_SIGNED + "=" + CryptoUtilities.generateSignedHex(transactionUuid, personalData.privateKey) + "&"
               + Constants.SESSION_UUID + "=" + ((WebAuthnPlus)personalData.getApplication()).getSessionUuid();

      String[] paramStrings  = CryptoUtilities.generateParams_CreateCredential(personalData.userData, personalData.publicKeyUuid, personalData.publicKeyHex);

      assert paramStrings != null;
      String urlParameters = paramStrings[0];
      String transferKeyHex = paramStrings[1];

      String[] urlStrings = {personalData.createCredentialUrl, urlParameters, transferKeyHex};

      /*
       * Send an asynch request through the ProcessCreateCredential inner class.
       */
      ProcessCreateCredential processCreateCredential = new ProcessCreateCredential(personalData);
      processCreateCredential.execute(urlStrings);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessCreateCredential extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<PersonalData> activityReference;

    // only retain a weak reference to the activity
    ProcessCreateCredential(PersonalData context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      PersonalData personalData = activityReference.get();

      if (!personalData.isNetworkAvailable()) {
        return personalData.getString(R.string.network_unavailable);
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

          return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, personalData);

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

      PersonalData personalData = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      personalData.progressDialog = new ProgressDialog(personalData);
      personalData.progressDialog.setCancelable(true);
      personalData.progressDialog.setTitle(personalData.getString(R.string.app_name));
      personalData.progressDialog.setMessage(personalData.getString(R.string.creating_credential));
      personalData.progressDialog.setIndeterminate(false);
      personalData.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      personalData.progressDialog.setProgress(0);
      personalData.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      PersonalData personalData = activityReference.get();

      log("RESULT::" + result + "::");

      personalData.progressDialog.dismiss();

      if (result == null) {
        result = personalData.getString(R.string.problem_with_authentication_server);
      }

      if (!result.contains(personalData.getString(R.string.credential_created))) {
        personalData.dataBaseManager.deleteCredentialByCredentialCredentialType(personalData.credentialType);
      } else {

        log("credentialUuid::" + personalData.credentialType + "::");
        log("indexOf::" + (result.indexOf(".") + 1) + "::");

        String jsonCredential = result.substring(result.indexOf(".") + 1);
        log("jsonCredential::" + jsonCredential + "::");

        personalData.dataBaseManager = new DataBaseManager(personalData);
        personalData.dataBaseManager.createJsonCredential(personalData.credentialType, jsonCredential, personalData.userSecurityKeyHex);

        result = result.substring(0, result.indexOf(".") + 1);
        log("result::" + result + "::");
      }

      Intent credentials = new Intent(personalData, Credentials.class);
      ((WebAuthnPlus)personalData.getApplication()).setCreateCredentialResult(result);

      personalData.startActivity(credentials);
    }
  }
}















