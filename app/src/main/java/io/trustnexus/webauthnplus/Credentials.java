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

package io.trustnexus.webauthnplus;

import android.app.AlertDialog;
import android.app.DialogFragment;
import android.app.NotificationManager;
import android.app.ProgressDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.ParcelUuid;
import android.preference.PreferenceManager;
import android.text.Html;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import io.trustnexus.webauthnplus.R;

import io.trustnexus.webauthnplus.util.Constants;
import io.trustnexus.webauthnplus.util.CryptoUtilities;
import io.trustnexus.webauthnplus.util.Utilities;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import androidx.annotation.NonNull;

import static android.provider.BaseColumns._ID;

public class Credentials extends ListActivityBase implements OnClickListener, AlertDialogFragmentDeleteCredential.OnDeleteCredentialListener {

  private SharedPreferences sharedPreferences;
  private String userSecurityKeyHex;
  private PrivateKey privateKey;

  private TextView credentialProviderName;
  private TextView urlAddress;
  private TextView authenticationCodeLabel;
  private TextView authenticationCode;

  private TextView messageZero;
  private byte[] credentialIconByteArray;
  private ImageView credentialIcon;
  private Button signOnButton;
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
  private String signOnUrl;
  private String cancelSignOnUrl;
  private String deleteCredentialUrl;
  private String retrieveTransactionUuidUrl;
  private String publicKeyUuid;
  private String publicKeyHex;

  private boolean processSignOnFlag;
  private boolean processCreateCredentialFlag;
  private boolean processDeleteCredentialFlag;
  private boolean processRetrieveCredentialMetaDataFlag;
  private boolean processCancelCreateCredentialFlag;
  private boolean processCancelSignOnFlag;

  private String requestType;
  private String domainName;
  private String sessionUuid;

  private DataBaseManager dataBaseManager;
  private ProgressDialog progressDialog;

  private boolean isBluetoothAvailable;
  private BluetoothManager bluetoothManager;
  private BluetoothLeAdvertiser bluetoothLeAdvertiser;
  private BluetoothGattServer bluetoothGattServer;
  private HashSet<BluetoothDevice> bluetoothDevicesSet;
  private String domainNameCharacteristicValue;
  private String sessionUuidCharacteristicValue;
  private BluetoothAdapter bluetoothAdapter;

  private static final String[] PERMISSIONS_ARRAY = {"android.permission.BLUETOOTH", "android.permission.BLUETOOTH_ADMIN",
                                                     "android.permission.ACCESS_FINE_LOCATION"};
  private static final int REQUEST_CODE_ASK_PERMISSIONS = 123;

  /*
   * Until a "Credential Service" is established by the Bluetooth SIG, we will utilize a custom defined service and characteristics.
   */
  private static final UUID CREDENTIAL_SERVICE = UUID.fromString("29143321-ef6c-4761-947c-c858f9a2e8f1");
  private static final UUID CREDENTIAL_UUID_CHARACTERISTIC = UUID.fromString("92f3131b-ffa8-4dd1-a12b-641d65a78857");
  private static final UUID DOMAIN_NAME_CHARACTERISTIC = UUID.fromString("0b9fcbba-1391-4411-8d53-a638b128496f");
  private static final UUID SESSION_UUID_CHARACTERISTIC = UUID.fromString("026ca15b-3357-4f0f-bc9c-dde367f9dd31");

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

    signOnButton = findViewById(R.id.sign_on_button);
    signOnButton.setOnClickListener(this);

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

    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {

      ArrayList<String> checkPermissionsList = new ArrayList<>();

      for (String permission : PERMISSIONS_ARRAY) {

        if (checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {

          checkPermissionsList.add(permission);
        }
      }

      if (checkPermissionsList.size() > 0) {
        requestPermissions(checkPermissionsList.toArray(new String[0]), REQUEST_CODE_ASK_PERMISSIONS);
      } else {
        displayCredentials();
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    // Set the "long click" function for deleting a credential.

    this.getListView().setLongClickable(true);

    this.getListView().setOnItemLongClickListener(new OnItemLongClickListener() {

      @Override
      public boolean onItemLongClick(AdapterView<?> adapter, View view, int position, long id) {

        if (!checkMaxIdleTimeExceeded()) {

          Cursor cursor = (Cursor) imageCursorAdapterCredentials.getItem(position);

          final int credentialId = cursor.getInt(cursor.getColumnIndex(_ID));

          log("credentialId: " + credentialId);

          new AlertDialog.Builder(Credentials.this)
                  .setTitle(cursor.getString(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_PROVIDER_NAME)))
                  .setItems(R.array.credential_options,
                          new DialogInterface.OnClickListener() {

                            @Override
                            public void onClick(DialogInterface dialog, int arrayValue) {

                              switch (arrayValue) {
                                case 0:

                                  DialogFragment alertDialogFragmentDeleteCredential = AlertDialogFragmentDeleteCredential.newInstance(credentialId);
                                  alertDialogFragmentDeleteCredential.show(getFragmentManager(), "dialog");

                                  dialog.dismiss();

                                  break;

                                case 1:
                                  dialog.dismiss();
                                  break;

                                default:
                                  break;
                              }
                            }
                          })
                  .show();

          return true;
        } else {
          return false;
        }
      }
    });

    // ----------------------------------------------------------------------------------------------------------------

    /*
     * The credential creation process begins when the user touches "Create" in this Activity.
     *
     * The user is then transferred to the PersonalData Intent to select the profile information he/she would like to
     * share.  The credential is then created and the user is then brought back to this Credential intent to display the,
     * "Credential successfully created.", message.
     *
     * If the createCredentialResult, which is stored in application scope, is not null or empty, then this Intent was
     * called from the PersonalData Intent and the user is attempting to create a new credential.
     *
     * Get and set the appropriate display values.
     */

    String createCredentialResult = ((WebAuthnPlus)getApplication()).getCreateCredentialResult();
    log("######## createCredentialResult: " + createCredentialResult);

    if (createCredentialResult != null && createCredentialResult.trim().length() > 1) {

      processCreateCredentialFlag = true;

      clearButton.setBackground(getResources().getDrawable(R.drawable.button_gradient));

      messageOne.setVisibility(TextView.VISIBLE);
      messageOne.setText(createCredentialResult);

      credentialProviderName.setVisibility(TextView.GONE);
      urlAddress.setVisibility(TextView.GONE);

      authenticationCodeLabel.setVisibility(TextView.GONE);
      authenticationCode.setVisibility(TextView.GONE);

      if (createCredentialResult.equalsIgnoreCase(getString(R.string.credential_created))) {

        String screenName = CryptoUtilities.decrypt(userSecurityKeyHex, sharedPreferences.getString( getString(R.string.screen_name_key), getString(R.string.empty_string)));

        messageZero.setVisibility(TextView.VISIBLE);
        String thankyouMessage = getString(R.string.thank_you) + " " + screenName.trim() + ".";
        messageZero.setText(thankyouMessage);
        messageZero.setTypeface(null, Typeface.BOLD);

        verificationCodeLabel.setVisibility(TextView.VISIBLE);
        verificationCode.setVisibility(TextView.VISIBLE);
        verificationCode.setText(((WebAuthnPlus)getApplication()).getVerificationCodeValue());
      }

      ((WebAuthnPlus)getApplication()).setCredentialProviderName(null);
      ((WebAuthnPlus)getApplication()).setDomainName(null);
      ((WebAuthnPlus)getApplication()).setAuthenticationCode(null);
      ((WebAuthnPlus)getApplication()).setSessionUuid(null);

      ((WebAuthnPlus)getApplication()).setCredentialIconByteArray(null);
      ((WebAuthnPlus)getApplication()).setCreateCredentialType(null);
      ((WebAuthnPlus)getApplication()).setCreateCredentialResult(null);
      ((WebAuthnPlus)getApplication()).setVerificationCodeValue(null);
    }

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
  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
    switch (requestCode) {
      case REQUEST_CODE_ASK_PERMISSIONS:

        boolean permissionsGranted = true;

        for (int grantResult : grantResults) {

          if (grantResult != PackageManager.PERMISSION_GRANTED) {
            permissionsGranted = false;
          }
        }

        if (permissionsGranted) {
          displayCredentials();
        } else {
          Toast.makeText(this, "PERMISSIONS DENIED!", Toast.LENGTH_SHORT).show();
        }
        break;
      default:
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private void processFirebaseMessage() {

    NotificationManager notificationManager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
    if (notificationManager != null) {
      notificationManager.cancel(Constants.TNX_NOTIFICATION);
    }

    String firebaseDataEncryptedHex = ((WebAuthnPlus)getApplication()).getFirebaseDataEncryptedHex();
    log("################################ firebaseDataEncryptedHex: " + firebaseDataEncryptedHex);
    log("################################ firebaseDataEncryptedHex length: " + firebaseDataEncryptedHex.length());

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

        String credentialIconUrl = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.CREDENTIAL_ICON_URL);
        log("################################ credentialIconUrl::" + credentialIconUrl + "::");

        String credentialProviderNameValue = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.CREDENTIAL_PROVIDER_NAME);
        log("################################ credentialProviderNameValue: " + credentialProviderNameValue);
        ((WebAuthnPlus)getApplication()).setCredentialProviderName(credentialProviderNameValue);

        domainName = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.DOMAIN_NAME);
        log("################################ domainName: " + domainName);
        ((WebAuthnPlus)getApplication()).setDomainName(domainName);

        String authenticationCodeValue = Utilities.parseNameValuePairs(transferDataDecrypted, Constants.AUTHENTICATION_CODE);
        log("################################ authenticationCodeValue: " + authenticationCodeValue);
        ((WebAuthnPlus)getApplication()).setAuthenticationCode(authenticationCodeValue);

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

        messageOne.setText(R.string.empty_string);
        messageOne.setVisibility(TextView.GONE);

        verificationCodeLabel.setVisibility(TextView.GONE);
        verificationCode.setVisibility(TextView.GONE);
        verificationCode.setText(R.string.empty_string);

        switch (requestType) {
          case Constants.FIREBASE_MSG_TYPE_CREATE_CREDENTIAL:

            authenticationCodeLabel.setVisibility(TextView.VISIBLE);
            authenticationCode.setVisibility(TextView.VISIBLE);
            authenticationCode.setText(authenticationCodeValue);

            messageZero.setText(R.string.bluetooth_instructions);
            messageZero.setTypeface(null, Typeface.BOLD);

            float scale = getResources().getDisplayMetrics().density;

            int paddingLeftRight = (int) (20 * scale + 0.5f);
            int paddingTopBottom = (int) (5 * scale + 0.5f);

            signOnButton.setBackground(getResources().getDrawable(R.drawable.button_gradient2));
            signOnButton.setText(R.string.create);
            signOnButton.setPadding(paddingLeftRight, paddingTopBottom, paddingLeftRight, paddingTopBottom);
            clearButton.setBackground(getResources().getDrawable(R.drawable.button_gradient));

            /*
             * Make an asynchronous call to get the credential icon image
             */
            String[] urlStrings = {credentialIconUrl};

            ProcessRetrieveCredentialIcon processRetrieveCredentialIcon = new ProcessRetrieveCredentialIcon(this);
            processRetrieveCredentialIcon.execute(urlStrings);

            break;
          case Constants.FIREBASE_MSG_TYPE_SIGN_ON:

            try {
              Cursor cursor = dataBaseManager.retrieveCredentialByCredentialType(credentialType);

              boolean hasResults = cursor.moveToFirst();
              log("hasResults: " + hasResults);

              if (hasResults) {
                ((WebAuthnPlus)getApplication()).setDomainName(domainName);

                String encryptedCredentialUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.ENCRYPTED_CREDENTIAL_UUID));
                String storedCredentialUuid = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedCredentialUuid);
                log("storedCredentialUuid: " + storedCredentialUuid);

                String storedDomainName = cursor.getString(cursor.getColumnIndex(DataBaseManager.DOMAIN_NAME));
                log("storedDomainName: " + storedDomainName);

                /*
                 * This is a check that the values from the Firebase message match the values stored on the mobile device.
                 */
                if (storedCredentialUuid.equals(credentialUuid) && storedDomainName.equals(domainName)) {

                  authenticationCodeLabel.setVisibility(TextView.VISIBLE);
                  authenticationCode.setVisibility(TextView.VISIBLE);
                  authenticationCode.setText(authenticationCodeValue);

                  messageZero.setText(R.string.bluetooth_instructions);
                  messageZero.setTypeface(null, Typeface.BOLD);

                  signOnButton.setBackground(getResources().getDrawable(R.drawable.button_gradient2));
                  clearButton.setBackground(getResources().getDrawable(R.drawable.button_gradient));

                  byte[] credentialIconByteArray = cursor.getBlob(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_ICON));

                  if (credentialIconByteArray != null && credentialIconByteArray.length > 1) {

                    scale = getResources().getDisplayMetrics().density;
                    int iconWidth = (int)(scale*41);
                    int iconHeight = (int)(scale*27);

                    log("####scale: " + scale + "  " + iconWidth + "  " + iconHeight);

                    ByteArrayInputStream imageStream = new ByteArrayInputStream(credentialIconByteArray);
                    Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
                    Bitmap credentialIconBitMapScaled = Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

                    credentialIcon.setImageBitmap(credentialIconBitMapScaled);

                  } else {
                    credentialIcon.setImageResource(R.mipmap.app_icon);
                  }

                  credentialIcon.setVisibility(ImageView.VISIBLE);

                } else {
                  messageZero.setText(R.string.problem_retrieving_credential_uuid);
                }

              } else {
                messageZero.setText(R.string.problem_retrieving_credential_type);
              }

            } finally {
              dataBaseManager.close();
            }
            break;
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

    log("android.os.Build.VERSION.SDK_INT " + android.os.Build.VERSION.SDK_INT);

    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {

      ArrayList<String> checkPermissionsList = new ArrayList<>();

      for (String s : PERMISSIONS_ARRAY) {

        if (checkSelfPermission(s) != PackageManager.PERMISSION_GRANTED) {
          checkPermissionsList.add(s);
        }
      }

      if (checkPermissionsList.size() > 0) {
        requestPermissions(checkPermissionsList.toArray(new String[0]), REQUEST_CODE_ASK_PERMISSIONS);
      } else {
        displayCredentials();
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    bluetoothDevicesSet = new HashSet<>();
    bluetoothManager = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
    assert bluetoothManager != null;
    bluetoothAdapter = bluetoothManager.getAdapter();

    /*
     * In the credential creation process this activity resumes from the PersonalData Intent (see comments above).
     * If that is the case we do not want to engage the GattServer.
     */
    if (bluetoothAdapter.isMultipleAdvertisementSupported() && !processCreateCredentialFlag) {
      isBluetoothAvailable = true;

      String deviceName = bluetoothAdapter.getName();
      boolean updateDeviceName = false;

      log("\n\n\n\n########AAA bluetoothAdapter.getName() " + deviceName + "  " + deviceName.length());

      if (!deviceName.contains("WebAuthn+ ")) {
        deviceName = "WebAuthn+ " + deviceName;
        updateDeviceName = true;
      }

      if (deviceName.length() > 29) {
        deviceName = deviceName.substring(0, 29);
        updateDeviceName = true;
      }

      if (updateDeviceName) {
        log("\n\n\n\n##### Resettting device name.");
        bluetoothAdapter.setName(deviceName);
      }

      bluetoothLeAdvertiser = bluetoothAdapter.getBluetoothLeAdvertiser();

      GattServerCallback gattServerCallback = new GattServerCallback();
      bluetoothGattServer = bluetoothManager.openGattServer(this, gattServerCallback);
      setupServer();
      startAdvertising();
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  private void setupServer() {
    log("entering setupServer()");

    domainNameCharacteristicValue = null;
    sessionUuidCharacteristicValue = null;

    BluetoothGattService bluetoothGattService = new BluetoothGattService(CREDENTIAL_SERVICE, BluetoothGattService.SERVICE_TYPE_PRIMARY);

    // ----------------------------------------------------------------------------------------------------------------

    BluetoothGattCharacteristic credentialUuidCharacteristic = new BluetoothGattCharacteristic(
            CREDENTIAL_UUID_CHARACTERISTIC,
            BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ);

    bluetoothGattService.addCharacteristic(credentialUuidCharacteristic);

    /*
     * Value set for testing.  This read characteristic is currently not used.
     * If implemented this value would come from code.
     */
    String credentialUuid = "92f3131b-ffa8-4dd0-a12a-640d65a08857";
    log("credentialUuid: " + credentialUuid);

    byte[] values = credentialUuid.getBytes(StandardCharsets.UTF_8);
    credentialUuidCharacteristic.setValue(values);

    // ----------------------------------------------------------------------------------------------------------------

    BluetoothGattCharacteristic domainNameCharacteristic = new BluetoothGattCharacteristic(
            DOMAIN_NAME_CHARACTERISTIC,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE);

    bluetoothGattService.addCharacteristic(domainNameCharacteristic);

    // ----------------------------------------------------------------------------------------------------------------

    BluetoothGattCharacteristic webauthnPlusSessionUuidCharacteristic = new BluetoothGattCharacteristic(
            SESSION_UUID_CHARACTERISTIC,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE);

    bluetoothGattService.addCharacteristic(webauthnPlusSessionUuidCharacteristic);

    // ----------------------------------------------------------------------------------------------------------------

    bluetoothGattServer.addService(bluetoothGattService);
  }

  // ------------------------------------------------------------------------------------------------------------------

  private void startAdvertising() {

    if (bluetoothLeAdvertiser == null) {
      return;
    }

    /*
     * https://stackoverflow.com/questions/31490649/bluetooth-peripheral-advertise-failed-data-too-large
     * https://developer.android.com/reference/android/bluetooth/le/AdvertiseCallback
     *
     * Great solution:  https://stackoverflow.com/questions/47229859/how-to-set-ble-advertisement-packets-device-name-field
     */
    log("\n\n\n\n######## bluetoothAdapter.getName() " + bluetoothAdapter.getName() + "  " + bluetoothAdapter.getName().length());

    ParcelUuid parcelUuid = new ParcelUuid(CREDENTIAL_SERVICE);

    AdvertiseSettings advertiseSettings = new AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .build();

    AdvertiseData advertiseData = new AdvertiseData.Builder()
            .setIncludeTxPowerLevel(true)
            .addServiceUuid(parcelUuid)
            .build();

    AdvertiseData advertiseScanResponse = new AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .build();

    AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
      @Override
      public void onStartFailure(int errorCode) {
        super.onStartFailure(errorCode);
        log("Not broadcasting: " + errorCode);
        switch (errorCode) {
          case ADVERTISE_FAILED_ALREADY_STARTED:
            log("ADVERTISE_FAILED_ALREADY_STARTED");
            break;
          case ADVERTISE_FAILED_DATA_TOO_LARGE:
            log("ADVERTISE_FAILED_DATA_TOO_LARGE");
            break;
          case ADVERTISE_FAILED_FEATURE_UNSUPPORTED:
            log("ADVERTISE_FAILED_FEATURE_UNSUPPORTED");
            break;
          case ADVERTISE_FAILED_INTERNAL_ERROR:
            log("ADVERTISE_FAILED_INTERNAL_ERROR");
            break;
          case ADVERTISE_FAILED_TOO_MANY_ADVERTISERS:
            log("ADVERTISE_FAILED_TOO_MANY_ADVERTISERS");
            break;
          default:
            log("Unhandled error: " + errorCode);
        }
      }

      @Override
      public void onStartSuccess(AdvertiseSettings settingsInEffect) {
        super.onStartSuccess(settingsInEffect);
        log("Advertising started");
      }
    };

    bluetoothLeAdvertiser.startAdvertising(advertiseSettings, advertiseData, advertiseScanResponse, advertiseCallback);
  }

  // ------------------------------------------------------------------------------------------------------------------

  protected void onPause() {
    super.onPause();
    stopAdvertising();
    stopServer();
  }

  private void stopServer() {
    if (bluetoothGattServer != null) {
      bluetoothGattServer.close();
    }
  }

  private void stopAdvertising() {
    if (bluetoothLeAdvertiser != null) {
      bluetoothLeAdvertiser.stopAdvertising(advertiseCallback);
    }
  }

  // ----------------------------------------------------------------------------------------------------------------

  private AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
    @Override
    public void onStartSuccess(AdvertiseSettings settingsInEffect) {
      log("Peripheral advertising started.");
    }

    @Override
    public void onStartFailure(int errorCode) {
      log("Peripheral advertising failed: " + errorCode);
    }
  };

  // ------------------------------------------------------------------------------------------------------------------
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
  /*
   * This method is the implementation of the interface AlertDialogFragmentDeleteCredential.OnDeleteCredentialListener
   */
  public void onDeleteCredential(String areYouSure, int credentialId) {

    /*
     * This method makes a call to the web application.  Like almost all methods that make a call to the web application
     * a call is first made to get a TransactionUuid (which adds security to the process), then from that inner class
     * control is transferred to another inner class, ProcessDeleteCredential, based on a flag,
     * processDeleteCredentialFlag, that is set in this method.
     */

    if (areYouSure.equalsIgnoreCase(getString(R.string.yes))) {

      Cursor cursor = dataBaseManager.retrieveCredentialById(credentialId);

      boolean hasResults = cursor.moveToFirst();
      log("hasResults: " + hasResults);

      retrieveTransactionUuidUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.RETRIEVE_TRANSACTION_UUID_URL));
      log("retrieveTransactionUuidUrl: " + retrieveTransactionUuidUrl);

      deleteCredentialUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.DELETE_CREDENTIAL_URL));
      log("deleteCredentialUrl: " + deleteCredentialUrl);

      String encryptedUserUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.ENCRYPTED_USER_UUID));
      userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedUserUuid);
      log("userUuid: " + userUuid);

      credentialType = cursor.getString(cursor.getColumnIndex(DataBaseManager.CREDENTIAL_TYPE));
      log("credentialType: " + credentialType);

      publicKeyUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY_UUID));
      log("publicKeyUuid: " + publicKeyUuid);

      publicKeyHex = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY));
      log("publicKeyHex: " + publicKeyHex);

      processDeleteCredentialFlag = true;

      String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey, publicKeyUuid, publicKeyHex);

      assert paramStrings != null;
      String urlParameters = paramStrings[0];
      String transferKeyHex = paramStrings[1];

      String[] urlStrings = {retrieveTransactionUuidUrl, urlParameters, transferKeyHex};

      ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
      processRetrieveTransactionUuid.execute(urlStrings);

      dataBaseManager.deleteCredentialById(credentialId);
      displayCredentials();

      dataBaseManager.close();
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

            if (requestType.equals(Constants.FIREBASE_MSG_TYPE_CREATE_CREDENTIAL)) {

              requestType = null;

              String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey,
                      Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

              assert paramStrings != null;
              String urlParameters = paramStrings[0];
              String transferKeyHex = paramStrings[1];

              String[] urlStrings = {Constants.RETRIEVE_MOBILE_APP_PROVIDER_TRANSACTION_UUID_URL, urlParameters, transferKeyHex};

              /*
               * This method makes a call to the web application.  Like almost all methods that make a call to the web
               * application a call is first made to get a TransactionUuid (which adds security to the process), then from
               * the ProcessRetrieveTransactionUuid inner class control is transferred to another inner class based on a
               * flag.  In this case the flags is processRetrieveCredentialMetaData.
               */
              processRetrieveCredentialMetaDataFlag = true;

              ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
              processRetrieveTransactionUuid.execute(urlStrings);

            } else if (requestType.equals(Constants.FIREBASE_MSG_TYPE_SIGN_ON)) {

              requestType = null;

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

                signOnUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.SIGN_ON_URL));
                log("signOnUrl: " + signOnUrl);

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
              processSignOnFlag = true;

              ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
              processRetrieveTransactionUuid.execute(urlStrings);
            }
          }

          break;

        case R.id.clear_button:

          clearDisplay();

          if (requestType != null && requestType.equals(Constants.FIREBASE_MSG_TYPE_CREATE_CREDENTIAL)) {

            requestType = null;

            String userUuidEncrypted = sharedPreferences.getString(getString(R.string.user_uuid_key), getString(R.string.empty_string));
            userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, userUuidEncrypted);
            log("userUuid: " + userUuid);

            String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey,
                    Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

            assert paramStrings != null;
            String urlParameters = paramStrings[0];
            String transferKeyHex = paramStrings[1];

            String[] urlStrings = {Constants.RETRIEVE_MOBILE_APP_PROVIDER_TRANSACTION_UUID_URL, urlParameters, transferKeyHex};

            processCancelCreateCredentialFlag = true;

            ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
            processRetrieveTransactionUuid.execute(urlStrings);

          } else if (requestType!= null && requestType.equals(Constants.FIREBASE_MSG_TYPE_SIGN_ON)) {

            requestType = null;

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

              cancelSignOnUrl = cursor.getString(cursor.getColumnIndex(DataBaseManager.CANCEL_SIGN_ON_URL));
              log("cancelSignOnUrl: " + cancelSignOnUrl);

              String encryptedUserUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.ENCRYPTED_USER_UUID));
              userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, encryptedUserUuid);
              log("userUuid: " + userUuid);

              publicKeyUuid = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY_UUID));
              log("publicKeyUuid: " + publicKeyUuid);

              publicKeyHex = cursor.getString(cursor.getColumnIndex(DataBaseManager.PUBLIC_KEY));
              log("publicKeyHex: " + publicKeyHex);

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
            processCancelSignOnFlag = true;

            ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
            processRetrieveTransactionUuid.execute(urlStrings);

          } else {
            clearDisplay();
          }

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

    signOnButton.setText(R.string.sign_on);
    signOnButton.setPadding(paddingLeftRight, paddingTopBottom, paddingLeftRight, paddingTopBottom);
    signOnButton.setBackground(getResources().getDrawable(R.drawable.button_gradient2));
    signOnButton.setOnClickListener(null);
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

    ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
    NetworkInfo networkInfo = null;
    if (connectivityManager != null) {
      networkInfo = connectivityManager.getActiveNetworkInfo();
    }

    return networkInfo != null && networkInfo.isConnected();
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private class GattServerCallback extends BluetoothGattServerCallback {

    @Override
    public void onConnectionStateChange(BluetoothDevice device, final int status, int newState) {

      super.onConnectionStateChange(device, status, newState);
      if (status == BluetoothGatt.GATT_SUCCESS) {
        if (newState == BluetoothGatt.STATE_CONNECTED) {
          bluetoothDevicesSet.add(device);
          log("Connected to device: " + device.getAddress());

          runOnUiThread(new Runnable() {
            @Override
            public void run() {
              messageZero.setVisibility(TextView.VISIBLE);
              messageZero.setText(R.string.bluetooth_pairing_successful);
            }
          });

        } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {

          bluetoothDevicesSet.remove(device);
          log("Disconnected from device");
        }
      } else {
        bluetoothDevicesSet.remove(device);
        // There are too many gatt errors (some of them not even in the documentation) so we just
        // show the error to the user.
        final String errorMessage = getString(R.string.status_errorWhenConnecting) + ": " + status;
        runOnUiThread(new Runnable() {
          @Override
          public void run() {
            Toast.makeText(Credentials.this, errorMessage, Toast.LENGTH_LONG).show();
          }
        });
        log("Error when connecting: " + status);
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    public void onCharacteristicReadRequest(BluetoothDevice device, int requestId, int offset,
                                            BluetoothGattCharacteristic characteristic) {
      super.onCharacteristicReadRequest(device, requestId, offset, characteristic);

      log("Device tried to read characteristic: " + characteristic.getUuid());
      log("Value: " + Arrays.toString(characteristic.getValue()));
      log("offset: " + offset);

      byte[] value = characteristic.getValue();

      for (byte b : value) {
        log("WRITE " + b);
      }

      String characteristicValue = new String(value, StandardCharsets.UTF_8);
      log("characteristicValue: " + characteristicValue);

      if (offset != 0) {
        log("offset != 0");
        bluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, offset, /* value (optional) */ null);
        return;
      }

      bluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, characteristic.getValue());
      log("GATT_SUCCESS");
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    public void onNotificationSent(BluetoothDevice device, int status) {
      super.onNotificationSent(device, status);
      log("Notification sent. Status: " + status);
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    public void onCharacteristicWriteRequest(BluetoothDevice device, int requestId,
                                             BluetoothGattCharacteristic characteristic, boolean preparedWrite, boolean responseNeeded,
                                             int offset, byte[] value) {

      super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite,
                                         responseNeeded, offset, value);


      for (int i = 0; i < value.length; i++) {
        log( "WRITE: " + i + " " + value[i]);
      }

      String characteristicValue = new String(value, StandardCharsets.UTF_8);

      if (characteristic.getUuid().equals(DOMAIN_NAME_CHARACTERISTIC)) {
        bluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null);
        domainNameCharacteristicValue = characteristicValue;
      } else if (characteristic.getUuid().equals(SESSION_UUID_CHARACTERISTIC)) {
        bluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null);
        sessionUuidCharacteristicValue = characteristicValue;
      }
      log("characteristicValue: " + characteristicValue + "  " + domainNameCharacteristicValue + "  " + sessionUuidCharacteristicValue);

      if (domainNameCharacteristicValue != null && sessionUuidCharacteristicValue != null) {

        log(domainNameCharacteristicValue + "  " + domainName + "  " + sessionUuidCharacteristicValue + "  " + sessionUuid);

        if (domainNameCharacteristicValue.equals(domainName) && sessionUuidCharacteristicValue.equals(sessionUuid)) {

          runOnUiThread(new Runnable() {
            @Override
            public void run() {

              /*
               * https://stackoverflow.com/questions/1529068/is-it-possible-to-have-multiple-styles-inside-a-textview
               * https://stackoverflow.com/questions/37904739/html-fromhtml-deprecated-in-android-n
               */

              String domainText = getString(R.string.domain_name_confirmed) + " <font color='#AA0000'>" + domainName + "</font>";

              messageOne.setVisibility(TextView.VISIBLE);
              messageOne.setTypeface(null, Typeface.BOLD);
              messageOne.setText(Html.fromHtml(domainText, Html.FROM_HTML_MODE_LEGACY));

              signOnButton.setBackground(getDrawable(R.drawable.button_gradient));
            }
          });
        }
      } else {
        // TODO: message for failure.
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
    private WeakReference<Credentials> activityReference;

    // only retain a weak reference to the activity
    ProcessRetrieveTransactionUuid(Credentials context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Credentials credentials = activityReference.get();

      log("Entering ProcessRetrieveTransactionUuid");

      if (!credentials.isNetworkAvailable()) {
        return credentials.getString(R.string.network_unavailable);
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

          String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, credentials);
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

      Credentials credentials = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      credentials.progressDialog = new ProgressDialog(credentials);
      credentials.progressDialog.setCancelable(true);
      credentials.progressDialog.setTitle(credentials.getString(R.string.app_name));
      credentials.progressDialog.setMessage(credentials.getString(R.string.retrieving_transaction_uuid));
      credentials.progressDialog.setIndeterminate(false);
      credentials.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      credentials.progressDialog.setProgress(0);
      credentials.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String transactionUuid) {

      Credentials credentials = activityReference.get();

      log("RESULT::" + transactionUuid + "::");

      credentials.progressDialog.dismiss();

      // --------------------------------------------------------------------------------------------------------------

      if (credentials.processRetrieveCredentialMetaDataFlag) {

        credentials.processRetrieveCredentialMetaDataFlag = false;

        String transferData = Constants.USER_UUID + "=" + credentials.userUuid + "&"
                + Constants.SESSION_UUID + "=" + credentials.sessionUuid + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, credentials.privateKey) + "&";

        String[] paramStrings = CryptoUtilities.generateParams_RetrieveCredentialMetaData(transferData,
                Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {Constants.RETRIEVE_CREDENTIAL_META_DATA_URL, urlParameters, transferKeyHex};

        ProcessRetrieveCredentialMetaData processRetrieveCredentialMetaData = new ProcessRetrieveCredentialMetaData(credentials);
        processRetrieveCredentialMetaData.execute(urlStrings);

      } else if (credentials.processCancelCreateCredentialFlag) {

        credentials.processCancelCreateCredentialFlag = false;

        String transferData = Constants.USER_UUID + "=" + credentials.userUuid + "&"
                + Constants.SESSION_UUID + "=" + credentials.sessionUuid + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, credentials.privateKey) + "&";

        String[] paramStrings = CryptoUtilities.generateParams_RetrieveCredentialMetaData(transferData,
                Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {Constants.CANCEL_CREATE_CREDENTIAL_URL, urlParameters, transferKeyHex};

        ProcessCancelCreateCredential processCancelCreateCredential = new ProcessCancelCreateCredential(credentials);
        processCancelCreateCredential.execute(urlStrings);

      } else if (credentials.processSignOnFlag) {

        credentials.processSignOnFlag = false;

        String transferData = Constants.VERIFICATION_CODE + "=" + credentials.verificationCodeValue + "&"
                + Constants.USER_UUID + "=" + credentials.userUuid + "&"
                + Constants.CREDENTIAL_UUID + "=" + credentials.credentialUuid + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, credentials.privateKey) + "&"
                + Constants.SESSION_UUID + "=" + credentials.sessionUuid + "&"
                + Constants.SESSION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(credentials.sessionUuid, credentials.privateKey) + "&";
        /*
         * Every transaction between the TNX WebAuthn Plus mobile app and the server includes a signed transactionUuid.
         * In this case, what we are most concerned with is the signed sessionUuid.  This value came to the
         * TNX WebAuthn Plus mobile app through an encrypted Firebase channel.
         */

        String[] paramStrings = CryptoUtilities.generateParams_CredentialSignOn(transferData, credentials.publicKeyUuid, credentials.publicKeyHex);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {credentials.signOnUrl, urlParameters, transferKeyHex};

        ProcessSignOn processSignOn = new ProcessSignOn(credentials);
        processSignOn.execute(urlStrings);

      } else if (credentials.processCancelSignOnFlag) {

        credentials.processCancelSignOnFlag = false;

        String transferData = Constants.USER_UUID + "=" + credentials.userUuid + "&"
                + Constants.CREDENTIAL_UUID + "=" + credentials.credentialUuid + "&"
                + Constants.SESSION_UUID + "=" + credentials.sessionUuid + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, credentials.privateKey) + "&";

        String[] paramStrings = CryptoUtilities.generateParams_RetrieveCredentialMetaData(transferData,
                Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID, Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {credentials.cancelSignOnUrl, urlParameters, transferKeyHex};

        ProcessCancelSignOn processCancelSignOn = new ProcessCancelSignOn(credentials);
        processCancelSignOn.execute(urlStrings);

      } else if (credentials.processDeleteCredentialFlag) {

        credentials.processDeleteCredentialFlag = false;

        String transferData = Constants.CREDENTIAL_TYPE + "=" + credentials.credentialType + "&"
                + Constants.USER_UUID + "=" + credentials.userUuid + "&"
                + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                + Constants.TRANSACTION_UUID_SIGNED + "="
                + CryptoUtilities.generateSignedHex(transactionUuid, credentials.privateKey) + "&";

        String[] paramStrings = CryptoUtilities.generateParams_DeleteCredential(transferData, credentials.publicKeyUuid, credentials.publicKeyHex);

        assert paramStrings != null;
        String urlParameters = paramStrings[0];
        String transferKeyHex = paramStrings[1];

        String[] urlStrings = {credentials.deleteCredentialUrl, urlParameters, transferKeyHex};

        ProcessDeleteCredential processDeleteCredential = new ProcessDeleteCredential(credentials);
        processDeleteCredential.execute(urlStrings);
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessRetrieveCredentialIcon extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Credentials> activityReference;

    // only retain a weak reference to the activity
    ProcessRetrieveCredentialIcon(Credentials context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Credentials credentials = activityReference.get();

      log("Entering ProcessRetrieveCredentialIcon");

      if (!credentials.isNetworkAvailable()) {
        return credentials.getString(R.string.network_unavailable);
      } else {

        String credentialImageUrlString = urlStrings[0];

        try {

          URL credentialIconUrl = new URL(credentialImageUrlString);
          URLConnection urlConnection = credentialIconUrl.openConnection();
          InputStream credentialIconInputStream = urlConnection.getInputStream();
          ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

          int bytesRead;
          byte[] byteBuffer = new byte[65536];

          while ((bytesRead = credentialIconInputStream.read(byteBuffer, 0, byteBuffer.length)) != -1) {
            byteArrayOutputStream.write(byteBuffer, 0, bytesRead);
          }

          byteArrayOutputStream.flush();
          log("credentialIcon byte length::" + byteArrayOutputStream.size() + "::");

          credentials.credentialIconByteArray = byteArrayOutputStream.toByteArray();
          ((WebAuthnPlus)credentials.getApplication()).setCredentialIconByteArray(credentials.credentialIconByteArray);

          return Constants.CREDENTIAL_ICON_DOWN_LOADED;

        } catch (Exception e) {
          e.printStackTrace();
          return credentials.getString(R.string.problem_retrieving_credential_icon);
        }
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    protected void onPreExecute() {

      Credentials credentials = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      credentials.progressDialog = new ProgressDialog(credentials);
      credentials.progressDialog.setCancelable(true);
      credentials.progressDialog.setTitle(credentials.getString(R.string.app_name));
      credentials.progressDialog.setMessage(credentials.getString(R.string.finding_credential_icon));
      credentials.progressDialog.setIndeterminate(false);
      credentials.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      credentials.progressDialog.setProgress(0);
      credentials.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Credentials credentials = activityReference.get();

      log("RESULT::" + result + "::");

      credentials.progressDialog.dismiss();

      // --------------------------------------------------------------------------------------------------------------

      if (result.equals(Constants.CREDENTIAL_ICON_DOWN_LOADED)) {

        if (credentials.credentialIconByteArray != null && credentials.credentialIconByteArray.length > 1) {

          log("credentialIconByteArray: " + credentials.credentialIconByteArray.length);

          float scale = credentials.getResources().getDisplayMetrics().density;
          int iconWidth = (int)(scale*41);
          int iconHeight = (int)(scale*27);

          log("\n\n\n\n####scale: " + scale + "  " + iconWidth + "  " + iconHeight);

          ByteArrayInputStream imageStream = new ByteArrayInputStream(credentials.credentialIconByteArray);
          Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
          Bitmap credentialIconBitMapScaled =   Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

          credentials.credentialIcon.setImageBitmap(credentialIconBitMapScaled);

        } else {
          credentials.credentialIcon.setImageResource(R.mipmap.app_icon);
        }

        credentials.credentialIcon.setVisibility(ImageView.VISIBLE);
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessRetrieveCredentialMetaData extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Credentials> activityReference;

    // only retain a weak reference to the activity
    ProcessRetrieveCredentialMetaData(Credentials context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Credentials credentials = activityReference.get();

      log("Entering ProcessRetrieveCredentialMetaData");

      if (!credentials.isNetworkAvailable()) {
        return credentials.getString(R.string.network_unavailable);
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

          log("response: " + response);

          bufferedReader.close();

          // ----------------------------------------------------------------------------------------------------------

          String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, credentials);
          log("responseString: " + responseString);

          if (responseString.equals(credentials.getString(R.string.problem_with_authentication_server))) {
            return responseString;
          } else if (areProviderNameValuePairsValid(responseString)) {

            String userUuidEncrypted = credentials.sharedPreferences.getString(credentials.getString(R.string.user_uuid_key), credentials.getString(R.string.empty_string));
            String userUuid = CryptoUtilities.decrypt(credentials.userSecurityKeyHex, userUuidEncrypted);
            log("userUuid: " + userUuid);

            /*
             * Store the credentialMetaDataNameValuePairs in the Android database.
             */
            credentials.dataBaseManager.createCredential(userUuid, credentials.userSecurityKeyHex, responseString);

            /*
             * Store the credential type for reference in the PersonalData activity where the credential is created.
             */
            credentials.credentialType = Utilities.parseNameValuePairs(responseString, Constants.CREDENTIAL_TYPE);
            ((WebAuthnPlus)credentials.getApplication()).setCreateCredentialType(credentials.credentialType);
            log("credentialType::" + credentials.credentialType + "::");

            // ------------------------------------------------------------------------------------------------------

            /*
             * Download the credential icon and save it to the data base.
             */

            String credentialIconUrlString = Utilities.parseNameValuePairs(responseString, Constants.CREDENTIAL_ICON_URL);
            log("credentialIconUrlString::" + credentialIconUrlString + "::");

            if (credentialIconUrlString.length() > 4) {

              URL credentialIconUrl = new URL(credentialIconUrlString);
              URLConnection urlConnection = credentialIconUrl.openConnection();
              InputStream credentialInputStream = urlConnection.getInputStream();
              ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

              int bytesRead;
              byte[] byteBuffer = new byte[65536];

              while ((bytesRead = credentialInputStream.read(byteBuffer, 0, byteBuffer.length)) != -1) {
                byteArrayOutputStream.write(byteBuffer, 0, bytesRead);
              }

              byteArrayOutputStream.flush();
              log("credentialIcon byte length::" + byteArrayOutputStream.size() + "::");

              byte[] credentialIconByteArray = byteArrayOutputStream.toByteArray();
              credentials.dataBaseManager.createCredentialIcon(credentials.credentialType, credentialIconByteArray);

              // TODO:  If icon image fails to load, send message to provider.
            }

            responseString = Constants.CREDENTIAL_PROVIDER_LOADED;

          } else {
            responseString = credentials.getString(R.string.provider_name_vale_pairs_invalid);
          }

          return responseString;

        } catch (Exception e) {
          log("Exception: " + e.getMessage());
          e.printStackTrace();
          return credentials.getString(R.string.problem_retrieving_credential_provider);
        } finally {
          if (connection != null) {
            connection.disconnect();
          }
        }
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    protected void onPreExecute() {

      Credentials credentials = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      credentials.progressDialog = new ProgressDialog(credentials);
      credentials.progressDialog.setCancelable(true);
      credentials.progressDialog.setTitle(credentials.getString(R.string.app_name));
      credentials.progressDialog.setMessage(credentials.getString(R.string.finding_credential_provider));
      credentials.progressDialog.setIndeterminate(false);
      credentials.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      credentials.progressDialog.setProgress(0);
      credentials.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Credentials credentials = activityReference.get();

      log("RESULT::" + result + "::");

      credentials.progressDialog.dismiss();

      // --------------------------------------------------------------------------------------------------------------

      if (result.equals(Constants.CREDENTIAL_PROVIDER_LOADED)) {

        /*
         * Transfer the user to the PersonalData Intent where the user can select how much personal data he/she wants to
         * send in the credential creation process.
         */
        Intent personalData = new Intent(credentials, PersonalData.class);
        credentials.startActivity(personalData);

      } else {

        credentials.messageZero.setText(result);

        credentials.credentialIcon.setVisibility(ImageView.GONE);

        credentials.credentialProviderName.setVisibility(TextView.GONE);
        credentials.urlAddress.setVisibility(TextView.GONE);

        credentials.authenticationCodeLabel.setVisibility(TextView.GONE);
        credentials.authenticationCode.setVisibility(TextView.GONE);

        credentials.verificationCodeLabel.setVisibility(TextView.GONE);
        credentials.verificationCode.setVisibility(TextView.GONE);
      }
    }

    // ----------------------------------------------------------------------------------------------------------------

    private boolean areProviderNameValuePairsValid(String providerNameValuePairs) {

      log("providerNameValuePairs::" + providerNameValuePairs + "::");

      boolean areProviderNameValuePairsValid = false;

      try {
        if (providerNameValuePairs != null) {

          String providerName = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.CREDENTIAL_PROVIDER_NAME);
          String credentialType = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.CREDENTIAL_TYPE);
          String displayName = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.CREDENTIAL_DISPLAY_NAME);
          String domainName = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.DOMAIN_NAME);
          String createCredentialUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.CREATE_CREDENTIAL_URL);
          String deleteCredentialUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.DELETE_CREDENTIAL_URL);
          String retrieveTransactionUuidUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.RETRIEVE_TRANSACTION_UUID_URL);
          String signOnUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.SIGN_ON_URL);
          String cancelSignOnUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.CANCEL_SIGN_ON_URL);
          String retrieveUnsignedDistributedLedgerUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL);
          String returnSignedDistributedLedgerUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.RETURN_SIGNED_DISTRIBUTED_LEDGER_URL);
          String credentialIconUrl = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.CREDENTIAL_ICON_URL);
          String publicKeyUuid = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.PUBLIC_KEY_UUID);
          String publicKey = Utilities.parseNameValuePairs(providerNameValuePairs, Constants.PUBLIC_KEY_HEX);

          if (providerName.length() > 0 && credentialType.length() > 0 && displayName.length() > 0 && domainName.length() > 0 && createCredentialUrl.length() > 0
                  && deleteCredentialUrl.length() > 0 && retrieveTransactionUuidUrl.length() > 0 && signOnUrl.length() > 0 && cancelSignOnUrl.length() > 0
                  && retrieveUnsignedDistributedLedgerUrl.length() > 0 && returnSignedDistributedLedgerUrl.length() > 0 && credentialIconUrl.length() > 0
                  && publicKeyUuid.length() > 0 && publicKey.length() > 0) {

            areProviderNameValuePairsValid = true;
          }
        }
      } catch (Exception e) {
        log(e.getMessage());
      }

      return areProviderNameValuePairsValid;
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessSignOn extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Credentials> activityReference;

    // only retain a weak reference to the activity
    ProcessSignOn(Credentials context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Credentials credentials = activityReference.get();

      log("Entering ProcessSignOn");

      if (!credentials.isNetworkAvailable()) {
        return credentials.getString(R.string.network_unavailable);
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

          return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, credentials);

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

      Credentials credentials = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      credentials.progressDialog = new ProgressDialog(credentials);
      credentials.progressDialog.setCancelable(true);
      credentials.progressDialog.setTitle(credentials.getString(R.string.app_name));
      credentials.progressDialog.setMessage(credentials.getString(R.string.authenticating));
      credentials.progressDialog.setIndeterminate(false);
      credentials.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      credentials.progressDialog.setProgress(0);
      credentials.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Credentials credentials = activityReference.get();

      log("RESULT::" + result + "::");

      credentials.progressDialog.dismiss();

      if (result == null) {
        result = credentials.getString(R.string.problem_with_authentication_server);
      }

      credentials.messageOne.setVisibility(TextView.VISIBLE);
      credentials.messageOne.setText(result);
      credentials.messageOne.setTypeface(null, Typeface.NORMAL);

      credentials.credentialIcon.setVisibility(ImageView.GONE);
      credentials.credentialProviderName.setVisibility(TextView.GONE);
      credentials.urlAddress.setVisibility(TextView.GONE);

      credentials.authenticationCodeLabel.setVisibility(TextView.GONE);
      credentials. authenticationCode.setVisibility(TextView.GONE);

      if (result.equalsIgnoreCase(credentials.getString(R.string.sign_on_successful))) {

        String screenName = CryptoUtilities.decrypt(credentials.userSecurityKeyHex, credentials.sharedPreferences.getString( credentials.getString(R.string.screen_name_key), credentials.getString(R.string.empty_string)));

        credentials.messageZero.setVisibility(TextView.VISIBLE);
        String welcomMessage = credentials.getString(R.string.welcome) + " " + screenName.trim();
        credentials.messageZero.setText(welcomMessage);
        credentials.messageZero.setTypeface(null, Typeface.BOLD);

        credentials.verificationCodeLabel.setVisibility(TextView.VISIBLE);
        credentials.verificationCode.setVisibility(TextView.VISIBLE);
        credentials.verificationCode.setText(((WebAuthnPlus)credentials.getApplication()).getVerificationCodeValue());
      }

      ((WebAuthnPlus)credentials.getApplication()).setSignOnSuccessful(true);

      ((WebAuthnPlus)credentials.getApplication()).setCredentialProviderName(null);
      ((WebAuthnPlus)credentials.getApplication()).setDomainName(null);
      ((WebAuthnPlus)credentials.getApplication()).setAuthenticationCode(null);
      ((WebAuthnPlus)credentials.getApplication()).setSessionUuid(null);

      ((WebAuthnPlus)credentials.getApplication()).setCredentialIconByteArray(null);
      ((WebAuthnPlus)credentials.getApplication()).setCreateCredentialType(null);
      ((WebAuthnPlus)credentials.getApplication()).setCreateCredentialResult(null);
      ((WebAuthnPlus)credentials.getApplication()).setVerificationCodeValue(null);

      credentials.signOnButton.setBackground(((WebAuthnPlus)credentials.getApplication()).getResources().getDrawable(R.drawable.button_gradient2));
      credentials.signOnButton.setOnClickListener(null);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessDeleteCredential extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Credentials> activityReference;

    // only retain a weak reference to the activity
    ProcessDeleteCredential(Credentials context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Credentials credentials = activityReference.get();

      log("Entering ProcessDeleteCredential");

      if (!credentials.isNetworkAvailable()) {
        return credentials.getString(R.string.network_unavailable);
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

          return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, credentials);

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

      Credentials credentials = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      credentials.progressDialog = new ProgressDialog(credentials);
      credentials.progressDialog.setCancelable(true);
      credentials.progressDialog.setTitle(credentials.getString(R.string.app_name));
      credentials.progressDialog.setMessage(credentials.getString(R.string.deleting_credential));
      credentials.progressDialog.setIndeterminate(false);
      credentials.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      credentials.progressDialog.setProgress(0);
      credentials.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Credentials credentials = activityReference.get();

      log("RESULT::" + result + "::");

      credentials.progressDialog.dismiss();

      if (result == null) {
        result = credentials.getString(R.string.problem_with_authentication_server);
      }

      credentials.authenticationCode.setTextColor(((WebAuthnPlus)credentials.getApplication()).getResources().getColor(R.color.low_key_color));
      credentials.authenticationCode.setTextSize(12);

      credentials.messageOne.setText(result);

      credentials.verificationCodeLabel.setVisibility(TextView.GONE);
      credentials.verificationCode.setVisibility(TextView.GONE);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessCancelCreateCredential extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Credentials> activityReference;

    // only retain a weak reference to the activity
    ProcessCancelCreateCredential(Credentials context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Credentials credentials = activityReference.get();

      log("Entering ProcessCancelCreateCredential");

      if (!credentials.isNetworkAvailable()) {
        return credentials.getString(R.string.network_unavailable);
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

          return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, credentials);

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

      Credentials credentials = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      credentials.progressDialog = new ProgressDialog(credentials);
      credentials.progressDialog.setCancelable(true);
      credentials.progressDialog.setTitle(credentials.getString(R.string.app_name));
      credentials.progressDialog.setMessage(credentials.getString(R.string.deleting_credential));
      credentials.progressDialog.setIndeterminate(false);
      credentials.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      credentials.progressDialog.setProgress(0);
      credentials.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Credentials credentials = activityReference.get();

      log("RESULT::" + result + "::");

      credentials.progressDialog.dismiss();

      if (result == null) {
        result = credentials.getString(R.string.problem_with_authentication_server);
      }

      credentials.authenticationCode.setTextColor(((WebAuthnPlus)credentials.getApplication()).getResources().getColor(R.color.low_key_color));
      credentials.authenticationCode.setTextSize(12);

      credentials.messageOne.setText(result);

      credentials.verificationCodeLabel.setVisibility(TextView.GONE);
      credentials.verificationCode.setVisibility(TextView.GONE);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  private static class ProcessCancelSignOn extends AsyncTask<String, Void, String> {

    /*
     * Thx Suragch
     * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
     */
    private WeakReference<Credentials> activityReference;

    // only retain a weak reference to the activity
    ProcessCancelSignOn(Credentials context) {
      activityReference = new WeakReference<>(context);
    }

    @Override
    protected String doInBackground(String... urlStrings) {

      Credentials credentials = activityReference.get();

      if (!credentials.isNetworkAvailable()) {
        return credentials.getString(R.string.network_unavailable);
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

          return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, credentials);

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

      Credentials credentials = activityReference.get();

      /*
       * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
       * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
       */
      credentials.progressDialog = new ProgressDialog(credentials);
      credentials.progressDialog.setCancelable(true);
      credentials.progressDialog.setTitle(credentials.getString(R.string.app_name));
      credentials.progressDialog.setMessage(credentials.getString(R.string.deleting_credential));
      credentials.progressDialog.setIndeterminate(false);
      credentials.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
      credentials.progressDialog.setProgress(0);
      credentials.progressDialog.show();
    }

    // ----------------------------------------------------------------------------------------------------------------

    @Override
    protected void onPostExecute(String result) {

      Credentials credentials = activityReference.get();

      log("RESULT::" + result + "::");

      credentials.progressDialog.dismiss();

      if (result == null) {
        result = credentials.getString(R.string.problem_with_authentication_server);
      }

      credentials.authenticationCode.setTextColor(((WebAuthnPlus)credentials.getApplication()).getResources().getColor(R.color.low_key_color));
      credentials.authenticationCode.setTextSize(12);

      credentials.messageOne.setText(result);

      credentials.verificationCodeLabel.setVisibility(TextView.GONE);
      credentials.verificationCode.setVisibility(TextView.GONE);
    }
  }
}







