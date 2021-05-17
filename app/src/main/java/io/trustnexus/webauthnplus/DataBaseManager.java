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

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import io.trustnexus.webauthnplus.util.Constants;
import io.trustnexus.webauthnplus.util.CryptoUtilities;
import io.trustnexus.webauthnplus.util.Utilities;

import static android.provider.BaseColumns._ID;

@SuppressWarnings("WeakerAccess")
public class DataBaseManager extends SQLiteOpenHelper {

  public static final String DATABASE_NAME = "tnx.db";
  public static final int DATABASE_VERSION = 143;

  public static final String CREDENTIALS_TABLE = "credentials";
  public static final String TIME = "time";
  public static final String ENCRYPTED_CREDENTIAL_UUID = "encryptedCredentialUuid";
  public static final String CREDENTIAL_PROVIDER_UUID = "credentialProviderUuid";
  public static final String CREDENTIAL_PROVIDER_NAME = "credentialProviderName";
  public static final String DOMAIN_NAME = "domainName";
  public static final String CREATE_CREDENTIAL_URL = "createCredentialUrl";
  public static final String DELETE_CREDENTIAL_URL = "deleteCredentialUrl";
  public static final String SIGN_ON_URL = "signOnUrl";
  public static final String CANCEL_SIGN_ON_URL = "cancelSignOnUrl";
  public static final String RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL = "retrieveUnsignedDistributedLedgerUrl";
  public static final String RETURN_SIGNED_DISTRIBUTED_LEDGER_URL = "returnSignedDistributedLedgerUrl";
  public static final String SEND_FUNDS_URL = "sendFundsUrl";
  public static final String RECEIVE_FUNDS_URL = "receiveFundsUrl";
  public static final String ACCEPT_FUNDS_URL = "acceptFundsUrl";
  public static final String CONFIRM_FUNDS_URL = "confirmFundsUrl";
  public static final String ENCRYPTED_USER_UUID = "encryptedUserUuid";
  public static final String RETRIEVE_TRANSACTION_UUID_URL = "retrieveTransactionUuidUrl";
  public static final String PUBLIC_KEY_UUID = "publicKeyUuid";
  public static final String PUBLIC_KEY = "publicKey";
  public static final String CREDENTIAL_TYPE = "credentialType";
  public static final String DISPLAY_NAME = "displayName";
  public static final String CREDENTIAL_ICON_URL = "credentialIconUrl";
  public static final String CREDENTIAL_ICON = "credentialIcon";
  public static final String ENCRYPTED_JSON_CREDENTIAL = "encryptedJsonCredential";
  public static String ORDER_BY = CREDENTIAL_PROVIDER_NAME;

  public static final String[] FROM_CREDENTIALS = { _ID, TIME, ENCRYPTED_CREDENTIAL_UUID, CREDENTIAL_PROVIDER_UUID,
          CREDENTIAL_PROVIDER_NAME, DOMAIN_NAME, SIGN_ON_URL, CANCEL_SIGN_ON_URL, RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL,
          RETURN_SIGNED_DISTRIBUTED_LEDGER_URL, SEND_FUNDS_URL, ACCEPT_FUNDS_URL, CONFIRM_FUNDS_URL,
          RECEIVE_FUNDS_URL, PUBLIC_KEY, PUBLIC_KEY_UUID, RETRIEVE_TRANSACTION_UUID_URL, CREDENTIAL_ICON, CREDENTIAL_TYPE,
          DISPLAY_NAME, ENCRYPTED_USER_UUID};

  public static final String[] FROM_CREDENTIAL = { _ID, TIME, ENCRYPTED_CREDENTIAL_UUID, CREDENTIAL_PROVIDER_UUID,
          CREDENTIAL_PROVIDER_NAME, DOMAIN_NAME, CREATE_CREDENTIAL_URL, DELETE_CREDENTIAL_URL, SIGN_ON_URL,
          CANCEL_SIGN_ON_URL, RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL, RETURN_SIGNED_DISTRIBUTED_LEDGER_URL,
          SEND_FUNDS_URL, RECEIVE_FUNDS_URL, ACCEPT_FUNDS_URL, CONFIRM_FUNDS_URL, PUBLIC_KEY_UUID, PUBLIC_KEY,
          RETRIEVE_TRANSACTION_UUID_URL, CREDENTIAL_ICON_URL, CREDENTIAL_ICON, CREDENTIAL_TYPE, DISPLAY_NAME,
          ENCRYPTED_USER_UUID, ENCRYPTED_JSON_CREDENTIAL};

  private final static boolean DEBUG = true;

  // ------------------------------------------------------------------------------------------------------------------

  /*
   * Elegant solution by Michael Baltaks
   * https://stackoverflow.com/questions/115008/how-can-we-print-line-numbers-to-the-log-in-java
   */
  public static void log(String message) {
    if (DEBUG) {
      String fullClassName = Thread.currentThread().getStackTrace()[3].getClassName();
      String className = fullClassName.substring(fullClassName.lastIndexOf(".") + 1);
      String methodName = Thread.currentThread().getStackTrace()[3].getMethodName();
      int lineNumber = Thread.currentThread().getStackTrace()[3].getLineNumber();

      Log.d(Constants.LOG_PREFIX, className + "." + methodName + "()::" + lineNumber + "::" + message);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  public DataBaseManager(Context context) {
    super(context, DATABASE_NAME, null, DATABASE_VERSION);
  }

  // -----------------------------------------------------------------------------------------------------------------

  @Override
  public void onCreate(SQLiteDatabase db) {

    db.execSQL("CREATE TABLE " + CREDENTIALS_TABLE + " (" + _ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + TIME + " INTEGER," + ENCRYPTED_CREDENTIAL_UUID + " TEXT," + CREDENTIAL_PROVIDER_UUID + " TEXT,"
            + CREDENTIAL_PROVIDER_NAME + " TEXT NOT NULL," + DOMAIN_NAME + " TEXT NOT NULL,"
            + CREATE_CREDENTIAL_URL + " TEXT NOT NULL," + DELETE_CREDENTIAL_URL + " TEXT NOT NULL,"
            + SIGN_ON_URL + " TEXT NOT NULL,"
            + CANCEL_SIGN_ON_URL + " TEXT NOT NULL,"
            + RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL + " TEXT NOT NULL,"
            + RETURN_SIGNED_DISTRIBUTED_LEDGER_URL + " TEXT NOT NULL,"
            + SEND_FUNDS_URL + " TEXT NOT NULL,"
            + RECEIVE_FUNDS_URL + " TEXT NOT NULL," + ACCEPT_FUNDS_URL + " TEXT NOT NULL,"
            + CONFIRM_FUNDS_URL + " TEXT NOT NULL," + ENCRYPTED_USER_UUID + " TEXT NOT NULL,"
            + RETRIEVE_TRANSACTION_UUID_URL + " TEXT NOT NULL," + PUBLIC_KEY_UUID + " TEXT NOT NULL,"
            + PUBLIC_KEY + " TEXT NOT NULL," + CREDENTIAL_TYPE + " TEXT NOT NULL," + DISPLAY_NAME + " TEXT NOT NULL,"
            + ENCRYPTED_JSON_CREDENTIAL + " TEXT," + CREDENTIAL_ICON_URL + " TEXT NOT NULL," + CREDENTIAL_ICON + " BLOB);");
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {

    db.execSQL("DROP TABLE IF EXISTS " + CREDENTIALS_TABLE);
    onCreate(db);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion) {
    onUpgrade(db, oldVersion, newVersion);
  }

  // ------------------------------------------------------------------------------------------------------------------

  /*
   * A convenience method for adding test data.
   */
  public void createTestCredentials(String userSecurityKeyHex) {

    this.createCredential(userSecurityKeyHex, "IVY Bank", "www.ivybank.com", "http://www.ivybank.com/createCredential.action",
            "http://www.ivybank.com/deleteCredential.action", "http://www.ivybank.com/webAuthnPlusSignOn.action",
            "http://www.ivybank.com/cancelWebAuthnPlusSignOn.action","http://www.ivybank.com/retrieveUnsignedDistributedLedgerUrl.action",
            "http://www.ivybank.com/returnSignedDistributedLedgerUrl.action",
            "http://www.ivybankA.com/sendFunds.action", "http://www.ivybank.com/receiveFunds.action",
            "http://www.ivybankA.com/acceptFunds.action", "http://www.ivybank.com/confirmFunds.action",
            "http://www.ivybank.com/retrieveTransactionUuid.action", "publicKeyUuidA", "testPublicKeyA",
            "http://www.ivybank.com/credentialIcon.action", "test1234A", "credentialUuidA", "com.ivybank.DISPLAY_ONLY", "IVY Bank Test 1");

    this.createCredential(userSecurityKeyHex, "M-mail", "www.mmail.com", "http://www.mmail.com/createCredential.action",
            "http://www.mmail.com/deleteCredential.action", "http://www.mmail.com/webAuthnPlusSignOn.action",
            "http://www.mmail.com/cancelWebAuthnPlusSignOn.action","http://www.mmail.com/retrieveUnsignedDistributedLedgerUrl.action",
            "http://www.mmail.com/returnSignedDistributedLedgerUrl.action",
            "http://www.mmail.com/sendFunds.action", "http://www.mmail.com/receiveFunds.action",
            "http://www.mmail.com/acceptFunds.action", "http://www.mmail.com/confirmFunds.action",
            "http://www.mmail.com/retrieveTransactionUuid.action", "publicKeyUuidB", "testPublicKeyB",
            "http://www.mmail.com/credentialIcon.action", "test1234B", "credentialUuidB", "com.MMAIL.DISPLAY_ONLY", "M-mail Test 1");

    this.createCredential(userSecurityKeyHex, "Texas Driver's License", "www.txdps.state.tx.us", "http://www.txdps.state.tx.us/createCredential.action",
            "http://www.txdps.state.tx.us/deleteCredential.action", "http://www.txdps.state.tx.us/webAuthnPlusSignOn.action",
            "http://www.txdps.state.tx.us/cancelWebAuthnPlusSignOn.action", "http://www.txdps.state.tx.us/retrieveUnsignedDistributedLedgerUrl.action",
            "http://www.txdps.state.tx.us/returnSignedDistributedLedgerUrl.action",
            "http://www.txdps.com/sendFunds.action", "http://www.txdps.com/receiveFunds.action",
            "http://www.txdps.com/acceptFunds.action", "http://www.txdps.com/confirmFunds.action",
            "http://www.txdps.state.tx.us/retrieveTransactionUuid.action", "publicKeyUuidC", "testPublicKeyC",
            "http://www.txdps.com/credentialIcon.action", "test1234C", "credentialUuidC", "com.TXDL.DISPLAY_ONLY", "TDL Test 1");

    this.createCredential(userSecurityKeyHex, "Med Insurance", "www.med_insurance.com", "http://www.med_insurance.com/createCredential.action",
            "http://www.med_insurance.com/deleteCredential.action", "http://www.med_insurance.com/webAuthnPlusSignOn.action",
            "http://www.med_insurance.com/cancelWebAuthnPlusSignOn.action", "http://www.med_insurance.com/retrieveUnsignedDistributedLedgerUrl.action",
            "http://www.med_insurance.com/returnSignedDistributedLedgerUrl.action",
            "http://www.med_insurance.com/sendFunds.action", "http://www.med_insurance.com/receiveFunds.action",
            "http://www.med_insurance.com/acceptFunds.action", "http://www.med_insurance.com/confirmFunds.action",
            "http://www.med_insurance.com/retrieveTransactionUuid.action", "publicKeyUuidD", "testPublicKeyD",
            "http://www.med_insurance.com/credentialIcon.action", "test1234D", "credentialUuidD", "com.med_insurance.DISPLAY_ONLY", "MED Test 1");

    this.createCredential(userSecurityKeyHex, "Social Network", "www.social.com", "http://www.social.com/createCredential.action",
            "http://www.social.com/deleteCredential.action", "http://www.social.com/webAuthnPlusSignOn.action",
            "http://www.social.com/cancelWebAuthnPlusSignOn.action", "http://www.social.com/retrieveUnsignedDistributedLedgerUrl.action",
            "http://www.social.com/returnSignedDistributedLedgerUrl.action",
            "http://www.social.com/sendFunds.action", "http://www.social.com/receiveFunds.action",
            "http://www.social.com/acceptFunds.action", "http://www.social.com/confirmFunds.action",
            "http://www.social.com/retrieveTransactionUuid.action", "publicKeyUuidE", "testPublicKeyE",
            "http://www.social.com/credentialIcon.action", "test1234E", "credentialUuidE", "com.social.DISPLAY_ONLY", "SOC Test 1");
  }

  // ------------------------------------------------------------------------------------------------------------------

  /*
   * This method is only used to create the test credentials.
   */
  public void createCredential(String userSecurityKeyHex, String credentialProviderName, String domainName,
                               String createCredentialUrl, String deleteCredentialUrl, String webAuthnPlusSignOnUrl, String cancelWebAuthnPlusSignOnUrl,
                               String retrieveUnsignedDistributedLedgerUrl, String returnSignedDistributedLedgerUrl,
                               String sendFundsUrl, String receiveFundsUrl, String acceptFundsUrl, String confirmFundsUrl,
                               String retrieveTransactionUuidUrl, String publicKeyUuid, String publicKey,
                               String credentialIconUrl, String userUuid, String credentialUuid, String credentialType,
                               String displayName) {

    String encryptedUserUuidHex = CryptoUtilities.encrypt(userSecurityKeyHex, userUuid);
    log("encryptedUserUuidHex: " + encryptedUserUuidHex);

    String encryptedCredentialUuidHex = CryptoUtilities.encrypt(userSecurityKeyHex, credentialUuid);
    log("encryptedCredentialUuidHex: " + encryptedCredentialUuidHex);

    SQLiteDatabase db = this.getWritableDatabase();

    ContentValues contentValues = new ContentValues();
    contentValues.put(TIME, System.currentTimeMillis());
    contentValues.put(CREDENTIAL_PROVIDER_NAME, credentialProviderName);
    contentValues.put(DOMAIN_NAME, domainName);
    contentValues.put(CREATE_CREDENTIAL_URL, createCredentialUrl);
    contentValues.put(DELETE_CREDENTIAL_URL, deleteCredentialUrl);
    contentValues.put(SIGN_ON_URL, webAuthnPlusSignOnUrl);
    contentValues.put(CANCEL_SIGN_ON_URL, cancelWebAuthnPlusSignOnUrl);
    contentValues.put(RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL, retrieveUnsignedDistributedLedgerUrl);
    contentValues.put(RETURN_SIGNED_DISTRIBUTED_LEDGER_URL, returnSignedDistributedLedgerUrl);
    contentValues.put(SEND_FUNDS_URL, sendFundsUrl);
    contentValues.put(RECEIVE_FUNDS_URL, receiveFundsUrl);
    contentValues.put(ACCEPT_FUNDS_URL, acceptFundsUrl);
    contentValues.put(CONFIRM_FUNDS_URL, confirmFundsUrl);
    contentValues.put(RETRIEVE_TRANSACTION_UUID_URL, retrieveTransactionUuidUrl);
    contentValues.put(PUBLIC_KEY_UUID, publicKeyUuid);
    contentValues.put(PUBLIC_KEY, publicKey);
    contentValues.put(CREDENTIAL_TYPE, credentialType);
    contentValues.put(DISPLAY_NAME, displayName);
    contentValues.put(CREDENTIAL_ICON_URL, credentialIconUrl);
    contentValues.put(ENCRYPTED_USER_UUID, encryptedUserUuidHex);
    contentValues.put(ENCRYPTED_CREDENTIAL_UUID, encryptedCredentialUuidHex);
    db.insertOrThrow(CREDENTIALS_TABLE, null, contentValues);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public void deleteTestCredentials() {
    this.deleteCredentialByCredentialCredentialType("com.MMAIL.DISPLAY_ONLY");
    this.deleteCredentialByCredentialCredentialType("com.ivybank.DISPLAY_ONLY");
    this.deleteCredentialByCredentialCredentialType("com.TXDL.DISPLAY_ONLY");
    this.deleteCredentialByCredentialCredentialType("com.med_insurance.DISPLAY_ONLY");
    this.deleteCredentialByCredentialCredentialType("com.social.DISPLAY_ONLY");
  }

  // -----------------------------------------------------------------------------------------------------------------

  /*
   * Unfortunately it is not possible to encrypt everything in a database, becasue then there is no way to search the
   * database.  We will encrypt to essential fields:  encryptedCredentialUuid and encryptedUserUuid.
   */
  public void createCredential(String userUuid, String userSecurityKeyHex, String credentialProviderNameValuePairs) {

    log("credentialProviderNameValuePairs::" + credentialProviderNameValuePairs + "::");

    SQLiteDatabase db = this.getWritableDatabase();

    ContentValues contentValues = new ContentValues();
    contentValues.put(TIME, System.currentTimeMillis());

    String encryptedCredentialUuid = CryptoUtilities.encrypt(userSecurityKeyHex, CryptoUtilities.generateUuid());
    log("encryptedCredentialUuid: " + encryptedCredentialUuid);
    contentValues.put(ENCRYPTED_CREDENTIAL_UUID, encryptedCredentialUuid);

    String credentialProviderUuid = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.CREDENTIAL_PROVIDER_UUID);
    log("credentialProviderUuid::" + credentialProviderUuid + "::");
    contentValues.put(CREDENTIAL_PROVIDER_UUID, credentialProviderUuid);

    String credentialProviderName = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.CREDENTIAL_PROVIDER_NAME);
    log("credentialProviderName::" + credentialProviderName + "::");
    contentValues.put(CREDENTIAL_PROVIDER_NAME, credentialProviderName);

    String domainName = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.DOMAIN_NAME);
    log("domainName::" + domainName + "::");
    contentValues.put(DOMAIN_NAME, domainName);

    String createCredentialUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.CREATE_CREDENTIAL_URL);
    log("createCredentialUrl::" + createCredentialUrl + "::");
    contentValues.put(CREATE_CREDENTIAL_URL, createCredentialUrl);

    String deleteCredentialUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.DELETE_CREDENTIAL_URL);
    log("deleteCredentialUrl::" + deleteCredentialUrl + "::");
    contentValues.put(DELETE_CREDENTIAL_URL, deleteCredentialUrl);

    String webAuthnPlusSignOnUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.SIGN_ON_URL);
    log("webAuthnPlusSignOnUrl::" + webAuthnPlusSignOnUrl + "::");
    contentValues.put(SIGN_ON_URL, webAuthnPlusSignOnUrl);

    String cancelWebAuthnPlusSignOnUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.CANCEL_SIGN_ON_URL);
    log("cancelWebAuthnPlusSignOnUrl::" + cancelWebAuthnPlusSignOnUrl + "::");
    contentValues.put(CANCEL_SIGN_ON_URL, cancelWebAuthnPlusSignOnUrl);

    String retrieveUnsignedDistributedLedgerUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL);
    log("retrieveUnsignedDistributedLedgerUrl::" + retrieveUnsignedDistributedLedgerUrl + "::");
    contentValues.put(RETRIEVE_UNSIGNED_DISTRIBUTED_LEDGER_URL, retrieveUnsignedDistributedLedgerUrl);

    String returnSignedDistributedLedgerUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.RETURN_SIGNED_DISTRIBUTED_LEDGER_URL);
    log("returnSignedDistributedLedgerUrl::" + returnSignedDistributedLedgerUrl + "::");
    contentValues.put(RETURN_SIGNED_DISTRIBUTED_LEDGER_URL, returnSignedDistributedLedgerUrl);

    String sendFundsUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, SEND_FUNDS_URL);
    log("sendFundsUrl::" + sendFundsUrl + "::");
    contentValues.put(SEND_FUNDS_URL, sendFundsUrl);

    String receiveFundsUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, RECEIVE_FUNDS_URL);
    log("receiveFundsUrl::" + receiveFundsUrl + "::");
    contentValues.put(RECEIVE_FUNDS_URL, receiveFundsUrl);

    String acceptFundsUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, ACCEPT_FUNDS_URL);
    log("acceptFundsUrl::" + acceptFundsUrl + "::");
    contentValues.put(ACCEPT_FUNDS_URL, acceptFundsUrl);

    String confirmFundsUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, CONFIRM_FUNDS_URL);
    log("confirmFundsUrl::" + confirmFundsUrl + "::");
    contentValues.put(CONFIRM_FUNDS_URL, confirmFundsUrl);

    String credentialIconUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.CREDENTIAL_ICON_URL);
    log("credentialIconUrl::" + credentialIconUrl + "::");
    contentValues.put(CREDENTIAL_ICON_URL, credentialIconUrl);

    String credentialType = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.CREDENTIAL_TYPE);
    log("credentialType::" + credentialType + "::");
    contentValues.put(CREDENTIAL_TYPE, credentialType);

    String displayName = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.CREDENTIAL_DISPLAY_NAME);
    log("displayName::" + displayName + "::");
    contentValues.put(DISPLAY_NAME, displayName);

    String retrieveTransactionUuidUrl = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.RETRIEVE_TRANSACTION_UUID_URL);
    log("retrieveTransactionUuidUrl::" + retrieveTransactionUuidUrl + "::");
    contentValues.put(RETRIEVE_TRANSACTION_UUID_URL, retrieveTransactionUuidUrl);

    String publicKeyUuid = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.PUBLIC_KEY_UUID);
    log("publicKeyUuid::" + publicKeyUuid + "::");
    contentValues.put(PUBLIC_KEY_UUID, publicKeyUuid);

    String publicKey = Utilities.parseNameValuePairs(credentialProviderNameValuePairs, Constants.PUBLIC_KEY_HEX);
    log("publicKey::" + publicKey + "::");
    contentValues.put(PUBLIC_KEY, publicKey);

    String encryptedUserUuid = CryptoUtilities.encrypt(userSecurityKeyHex, userUuid);
    log("encryptedUserUuid: " + encryptedUserUuid);
    contentValues.put(ENCRYPTED_USER_UUID, encryptedUserUuid);

    // ----------------------------------------------------------------------------------------------------------------

    db.insertOrThrow(CREDENTIALS_TABLE, null, contentValues);

    log("Credential created.");
  }

  // -----------------------------------------------------------------------------------------------------------------

  public void createCredentialIcon(String credentialProviderType, byte[] credentialIconBytes) {

    if (credentialIconBytes != null) {

      SQLiteDatabase db = this.getWritableDatabase();

      ContentValues contentValues = new ContentValues();
      contentValues.put(CREDENTIAL_ICON, credentialIconBytes);
      String filter = CREDENTIAL_TYPE + "= ? ";
      String[] filterArgs = new String[]{ credentialProviderType };

      db.update(CREDENTIALS_TABLE, contentValues, filter, filterArgs);

      log("credentialIcon byte length::" + credentialIconBytes.length + "::");
      log("Credential icon successfully loaded.");
    }
  }

  // -----------------------------------------------------------------------------------------------------------------

  public void createJsonCredential(String credentialType, String jsonCredential, String userSecurityKeyHex) {

    if (jsonCredential != null) {

      log("credentialType: " + credentialType);

      String encryptedJsonCredential = CryptoUtilities.encrypt(userSecurityKeyHex, jsonCredential);
      log("encryptedJsonCredential: " + encryptedJsonCredential);

      SQLiteDatabase db = this.getWritableDatabase();

      ContentValues contentValues = new ContentValues();
      contentValues.put(ENCRYPTED_JSON_CREDENTIAL, encryptedJsonCredential);
      String filter = CREDENTIAL_TYPE + "= ? ";
      String[] filterArgs = new String[]{ credentialType };

      db.update(CREDENTIALS_TABLE, contentValues, filter, filterArgs);

      log("JSON CREDENTIAL SUCCESSFULLY LOADED");
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  public Cursor retrieveCredentials() {
    SQLiteDatabase db = this.getReadableDatabase();
    return db.query(CREDENTIALS_TABLE, FROM_CREDENTIALS, null, null, null, null, ORDER_BY);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public Cursor retrieveCredentialById(int credentialId) {
    SQLiteDatabase db = this.getReadableDatabase();
    return db.query(CREDENTIALS_TABLE, FROM_CREDENTIAL, _ID + "=?",
            new String[] {String.valueOf(credentialId)}, null, null, ORDER_BY);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public Cursor retrieveCredentialByCredentialProviderName(String credentialProviderName) {
    SQLiteDatabase db = this.getReadableDatabase();
    return db.query(CREDENTIALS_TABLE, FROM_CREDENTIAL, CREDENTIAL_PROVIDER_NAME + "=?",
            new String[] { credentialProviderName }, null, null, ORDER_BY);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public Cursor retrieveCredentialLikeCredentialType(String credentialProviderName) {
    SQLiteDatabase db = this.getReadableDatabase();
    return db.query(CREDENTIALS_TABLE, FROM_CREDENTIAL, CREDENTIAL_TYPE + " LIKE ?",
            new String[] { "%" + credentialProviderName + "%" }, null, null, ORDER_BY);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public Cursor retrieveCredentialByCredentialType(String credentialType) {
    SQLiteDatabase db = this.getReadableDatabase();
    return db.query(CREDENTIALS_TABLE, FROM_CREDENTIAL, CREDENTIAL_TYPE + "=?",
            new String[] {credentialType}, null, null, ORDER_BY);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public void deleteCredentialById(int credentialId) {
    SQLiteDatabase db = this.getWritableDatabase();
    db.delete(CREDENTIALS_TABLE, _ID + "=?", new String[] {String.valueOf(credentialId)} );
    log(credentialId + " SUCCESSFULLY DELETED");
  }

  // ------------------------------------------------------------------------------------------------------------------

  public void deleteCredentialByCredentialCredentialType(String credentialType) {
    SQLiteDatabase db = this.getWritableDatabase();
    db.delete(CREDENTIALS_TABLE, CREDENTIAL_TYPE + "=?", new String[] {credentialType} );
    log(" CREDENTIAL SUCCESSFULLY DELETED.  CREDENTIAL TYPE: " + credentialType);
  }
}







