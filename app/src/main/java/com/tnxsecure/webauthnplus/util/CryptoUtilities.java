package com.tnxsecure.webauthnplus.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Log;

import com.tnxsecure.webauthnplus.R;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtilities {

  private static final String HEX_DIGITS = "0123456789ABCDEF";
  private static final String END_OF_TRANSMISSION_BLOCK = "&ETB";

  private static final int IV_LENGTH = 16;
  private static final int SALT_LENGTH = 256;
  private static final int SECRET_KEY_LENGTH = 256;
  private static final int PUBLIC_PRIVATE_KEY_LENGTH = 4096;

  private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String KEY_FACTORY_ALGORITHM = "RSA";
  public static final String MAC_ALGORITHM = "HmacSHA256";
  public static final String RSA_CIPHER_ALGORITHM = "RSA/None/PKCS1Padding";
  public static final String SECRET_KEY_ALGORITHM = "AES";
  public static final String SECURE_HASH_ALGORITHM = "SHA-512";
  public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
  private static final String WRAPPING_CIPHER_ALGORITHM = "AESWrap";

  /*
   *  If all your users have newer phones (Android 8.0 Oreo ~ API 26), you might consider using PBKDF2WithHmacSHA512.
   *  https://stackoverflow.com/questions/19348501/pbkdf2withhmacsha512-vs-pbkdf2withhmacsha1
   *  https://developer.android.com/reference/javax/crypto/SecretKeyFactory
   */
  private static final String PBE_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA1";
  private static final int PBE_ITERATION_COUNT = 65536;  // TODO: 262144;
  private static final int PBE_KEY_LENGTH = 256;

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
  // ------------------------------------------------------------------------------------------------------------------

  public static String generateUuid() {
    return System.currentTimeMillis() + "-" + UUID.randomUUID().toString().toUpperCase();
  }

  public static String generateUuidPure() {
    return UUID.randomUUID().toString().toUpperCase();
  }

  // ------------------------------------------------------------------------------------------------------------------

  private static String toHex(byte[] data, int length) {

    StringBuilder stringBuilder = new StringBuilder();

    for (int i = 0; i != length; i++) {
      int v = data[i] & 0xff;

      stringBuilder.append(HEX_DIGITS.charAt(v >> 4));
      stringBuilder.append(HEX_DIGITS.charAt(v & 0xf));
    }

    return stringBuilder.toString();
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String toHex(byte[] data) {
    return toHex(data, data.length);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static byte[] hexStringToByteArray(String hexString) {

    int hexStringLength = hexString.length();
    byte[] data = new byte[hexStringLength / 2];

    for (int i = 0; i < hexStringLength; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
    }
    return data;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String unwrapKey(String wrappingKeyHex, String wrappedKeyHex) {

    try {
      Key wrappingKey = new SecretKeySpec(hexStringToByteArray(wrappingKeyHex), SECRET_KEY_ALGORITHM);

      Cipher wrappingCipher = Cipher.getInstance(WRAPPING_CIPHER_ALGORITHM);
      wrappingCipher.init(Cipher.UNWRAP_MODE, wrappingKey);

      Key keyUnwrapped = wrappingCipher.unwrap(hexStringToByteArray(wrappedKeyHex), SECRET_KEY_ALGORITHM, Cipher.SECRET_KEY);

      return toHex(keyUnwrapped.getEncoded());

    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String encrypt(String keyHex, String data) {

    String dataEncryptedHex = null;

    /*
     * Mark the end of data in order to remove padding later.
     */
    data += END_OF_TRANSMISSION_BLOCK;

    try {
      Key key = new SecretKeySpec(hexStringToByteArray(keyHex.trim()), SECRET_KEY_ALGORITHM);

      byte[] dataBytes = data.getBytes();

      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[IV_LENGTH];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));

      byte[] dataEncryptedBytes = new byte[cipher.getOutputSize(dataBytes.length)];

      int dataEncryptionPointer = cipher.update(dataBytes, 0, dataBytes.length, dataEncryptedBytes);
      dataEncryptionPointer += cipher.doFinal(dataEncryptedBytes, dataEncryptionPointer);

      dataEncryptedHex = toHex(ivBytes) + toHex(dataEncryptedBytes);
      log("dataEncryptedHex: " + dataEncryptedHex + "  length: " + dataEncryptedHex.length()
              + "dataEncryptionPointer: " + dataEncryptionPointer);

    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | ShortBufferException |
             InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return dataEncryptedHex;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String decrypt(String keyHex, String dataEncryptedHex) {

    log("dataEncryptedHex: " + dataEncryptedHex);

    if (dataEncryptedHex == null || dataEncryptedHex.length() < 32) {
      return "";
    }

    String dataDecrypted = null;

    try {

      Key key = new SecretKeySpec(hexStringToByteArray(keyHex), SECRET_KEY_ALGORITHM);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

      /*
       * The first sixteen bytes, thirty-two HEX characters, of the encrypted data
       * represents the initialization vector.
       */
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(CryptoUtilities.hexStringToByteArray(dataEncryptedHex.substring(0, 32))));

      byte[] dataEncryptedBytes = CryptoUtilities.hexStringToByteArray(dataEncryptedHex.substring(32));
      byte[] dataDecryptedBytes = new byte[cipher.getOutputSize(dataEncryptedBytes.length)];

      int dataDecryptionPointer = cipher.update(dataEncryptedBytes, 0, dataEncryptedBytes.length, dataDecryptedBytes, 0);
      dataDecryptionPointer += cipher.doFinal(dataDecryptedBytes, dataDecryptionPointer);

      log("dataDecryptedHex: " + CryptoUtilities.toHex(dataDecryptedBytes)
              + "dataDecryptionPointer: " + dataDecryptionPointer);

      /*
       * Convert the decrypted byte array into a human readable string.
       */
      dataDecrypted = new String(dataDecryptedBytes);
      log("dataDecrypted: " + dataDecrypted);

      /*
       * Remove padding.
       */
      dataDecrypted = dataDecrypted.substring(0, dataDecrypted.indexOf(END_OF_TRANSMISSION_BLOCK));
      log("dataDecrypted: " + dataDecrypted);

    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException |
            IllegalBlockSizeException | ShortBufferException | BadPaddingException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return dataDecrypted;
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  public static PrivateKey retrieveUserPrivateKey(String userSecurityKeyHex, String encryptedPrivateKeyHex) {

    log("Entering");

    String privateKeyHex = decrypt(userSecurityKeyHex, encryptedPrivateKeyHex);

    PrivateKey privateKey = null;

    try {

      privateKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePrivate(new PKCS8EncodedKeySpec(hexStringToByteArray(privateKeyHex)));

    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return privateKey;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String generateSignedHex(String unsignedElement, PrivateKey privateKey) {

    log("Entering");

    String signedElement = null;

    try {
      /*
       * Use the privateKey to sign the unsignedElement.
       */
      Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      signature.initSign(privateKey);
      signature.update(unsignedElement.getBytes());

      byte[]  signedBytes = signature.sign();

      signedElement = toHex(signedBytes);

    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return signedElement;
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  /*
   * If the user has not yet been created, he/she has no security credentials
   * (i.e., no private/public key); therefore, it is not possible to sign a transaction UUID.
   */
  public static String[] generateParams_CreateUser(SharedPreferences sharedPreferences, Context context) {

    log("Entering");

    try {

      /*
       * Create the transferKey then encrypt it with the mobile app provider public key.
       * This will be packageOne in the HTTP request.
       *
       * The transferKey is used to encrypt the user data that is sent to the mobile app provider
       * Authentication Server.
       */
      KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generator.init(SECRET_KEY_LENGTH);
      Key transferKey = generator.generateKey();

      // --------------------------------------------------------------------------------------------------------------

      PublicKey publicKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(hexStringToByteArray(Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY)));

      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] transferKeyEncryptedBytes = rsaCipher.doFinal(transferKey.getEncoded());

      String transferKeyEncryptedHex = toHex(transferKeyEncryptedBytes);
      log("transferKeyEncryptedHex: " + transferKeyEncryptedHex);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * At this point in the process the shared preferences values are not yet encrypted.
       */

      String transferData = Constants.SCREEN_NAME + "=" + sharedPreferences.getString(context.getString(R.string.screen_name_key), context.getString(R.string.empty_string)) + "&"
              + Constants.EMAIL + "=" + sharedPreferences.getString(context.getString(R.string.email_key), context.getString(R.string.empty_string)) + "&"
              + Constants.PHONE + "=" + sharedPreferences.getString(context.getString(R.string.phone_key), context.getString(R.string.empty_string)) + "&"
              + Constants.FIRST_NAME + "=" + sharedPreferences.getString(context.getString(R.string.first_name_key), context.getString(R.string.empty_string)) + "&"
              + Constants.LAST_NAME + "=" + sharedPreferences.getString(context.getString(R.string.last_name_key), context.getString(R.string.empty_string)) + "&"
              + Constants.USER_UUID + "=" + sharedPreferences.getString(context.getString(R.string.user_uuid_key), context.getString(R.string.empty_string))  + "&"
              + Constants.FIRE_BASE_DEVICE_ID + "=" + sharedPreferences.getString(context.getString(R.string.firebase_device_id), context.getString(R.string.empty_string))  + "&"

              + Constants.LEGAL_ADDRESS_LINE_ONE + "=" + sharedPreferences.getString(context.getString(R.string.legal_address_line_one_key), context.getString(R.string.empty_string)) + "&"
              + Constants.LEGAL_ADDRESS_LINE_TWO + "=" + sharedPreferences.getString(context.getString(R.string.legal_address_line_two_key), context.getString(R.string.empty_string)) + "&"
              + Constants.LEGAL_ADDRESS_CITY + "=" + sharedPreferences.getString(context.getString(R.string.legal_address_city_key), context.getString(R.string.empty_string)) + "&"
              + Constants.LEGAL_ADDRESS_STATE + "=" + sharedPreferences.getString(context.getString(R.string.legal_address_state_key), context.getString(R.string.empty_string)) + "&"
              + Constants.LEGAL_ADDRESS_POSTAL_CODE + "=" + sharedPreferences.getString(context.getString(R.string.legal_address_postal_code_key), context.getString(R.string.empty_string)) + "&"
              + Constants.LEGAL_ADDRESS_COUNTRY + "=" + sharedPreferences.getString(context.getString(R.string.legal_address_country_key), context.getString(R.string.empty_string)) + "&";

      byte[] transferDataBytes = transferData.getBytes();

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Encrypt the user data with the transferKey.
       */
      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[IV_LENGTH];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, transferKey, new IvParameterSpec(ivBytes));

      byte[] transferDataEncryptedBytes = new byte[cipher.getOutputSize(transferDataBytes.length)];

      int transferDataEncryptionPointer = cipher.update(transferDataBytes, 0, transferDataBytes.length, transferDataEncryptedBytes);
      transferDataEncryptionPointer += cipher.doFinal(transferDataEncryptedBytes, transferDataEncryptionPointer);
      log("transferDataEncryptionPointer: " + transferDataEncryptionPointer);

      String transferDataEncryptedHex = toHex(ivBytes) + toHex(transferDataEncryptedBytes);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create a "Message Authentication Code" (MAC) for the transferDataEncryptedHex
       * using the transferKey.  The MAC will insure message integrity.
       */
      Mac macTransferData = Mac.getInstance(MAC_ALGORITHM);
      macTransferData.init(transferKey);
      byte[] transferDataEncryptedHashedBytes = macTransferData.doFinal(transferDataEncryptedHex.getBytes());

      String transferDataEncryptedHashedHex = toHex(transferDataEncryptedHashedBytes);  // TODO: rename to transferDataMAC
      log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String urlParameters = Constants.PUBLIC_KEY_UUID_LABEL + "=" + Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID
              + "&" + Constants.TRANSFER_KEY_ENCRYPTED_HEX + "=" + transferKeyEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HEX + "=" + transferDataEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX + "=" + transferDataEncryptedHashedHex;

      return new String[]{urlParameters, toHex(transferKey.getEncoded())};

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
            IllegalBlockSizeException | InvalidAlgorithmParameterException | ShortBufferException | InvalidKeySpecException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_CreateSecurityKey(String password, SharedPreferences sharedPreferences, Context context) {

    log("Entering");

    Editor prefEditor = sharedPreferences.edit();

    try {

      /*
       * Create the transferKey then encrypt it with the mobile app provider public key.
       * This will be packageOne in the HTTP request.
       *
       * The transferKey is used to encrypt the user data that is sent to the mobile app provider
       * Authentication Server.
       */
      KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generator.init(SECRET_KEY_LENGTH);
      Key transferKey = generator.generateKey();

      // --------------------------------------------------------------------------------------------------------------

      PublicKey publicKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(hexStringToByteArray(Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY)));

      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] transferKeyEncryptedBytes = rsaCipher.doFinal(transferKey.getEncoded());

      String transferKeyEncryptedHex = toHex(transferKeyEncryptedBytes);
      log("transferKeyEncryptedHex: " + transferKeyEncryptedHex);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create the userIdentifier starting with a password based encryption key.
       *
       * The userIdentifier is recreated by the user every time he/she enters his/her PIN.
       * The userIdentifier is used to confirm the user's identity with the Authentication Server.
       */
      char[] passwordBytes = password.toCharArray();

      SecureRandom secureRandom = new SecureRandom();
      byte salt[] = new byte[SALT_LENGTH];
      secureRandom.nextBytes(salt);

      /*
       * Store the SALT in the shared preferences for future reference.
       */
      String saltHex = toHex(salt);
      log("saltHex: " + saltHex);

      prefEditor.putString(context.getString(R.string.crypto_salt_key), saltHex);

      /*
       *  TODO:  Update to Argon2 when it become available in Android.
       *  Unfortunately:  "Your search - site:developer.android.com argon2 - did not match any documents."
       */

      long begTime = System.currentTimeMillis();

      /*
       * Reference:
       * http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
       */
      SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBE_KEY_FACTORY_ALGORITHM);
      PBEKeySpec pbeKeySpec = new PBEKeySpec(passwordBytes, salt, PBE_ITERATION_COUNT, PBE_KEY_LENGTH);
      Key tempSecretKey = secretKeyFactory.generateSecret(pbeKeySpec);
      Key secretKey = new SecretKeySpec(tempSecretKey.getEncoded(), SECRET_KEY_ALGORITHM);

      log("secretKey: " + toHex(secretKey.getEncoded()));

      long endTime = System.currentTimeMillis();

      log("\n\n\n\n####pbeKeySpec genTime: " + (endTime - begTime));

      /*
       * Create the obfuscatedIdentifier.  Start by generating a UUID.
       */
      String obfuscatedIdentifier = CryptoUtilities.generateUuid();
      log("userIdentifier: " + obfuscatedIdentifier);

      /*
       * Store the obfuscatedIdentifier UUID in the shared preferences for future reference.
       *
       * When the obfuscatedIdentifier is hashed with the sceretKey it is used
       * as an obfuscated identifier to obtain the user's userSecurityKey (i.e., the
       * key that is used to encrypt/decrypt user data).
       */

      prefEditor.putString(context.getString(R.string.obfuscated_identifier_key), obfuscatedIdentifier);
      prefEditor.apply();

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Hash the obfuscatedIdentifier using the secretKey.
       */
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(secretKey);
      byte[] obfuscateIdentifierHashedBytes = mac.doFinal(obfuscatedIdentifier.getBytes());

      String obfuscateIdentifierHashedHex = toHex(obfuscateIdentifierHashedBytes);
      log("obfuscateIdentifierHashedHex: " + obfuscateIdentifierHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create the userSecurityKey that will be used to encrypt/decrypt user data.
       *
       * This userSecurityKey is NEVER stored on the user's system.  THe key is sent
       * to the TNX Authentication Server during user initialization and then returned
       * to the user after a successful login.
       */
      KeyGenerator generatorPrimary = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generatorPrimary.init(SECRET_KEY_LENGTH);
      Key userSecurityKey = generatorPrimary.generateKey();

      String userSecurityKeyHex = toHex(userSecurityKey.getEncoded());
      log("\n\n\n\n########userSecurityKey: " + userSecurityKeyHex);

      /*
       * Use the secretKey generated by the user passsword and the stored SALT to encrypt the userSecurityKeyHex.
       * This encrypted value is not stored on the user's mobile device; it is stored in the server database
       * (table: SecurityKey) along with the obfuscateIdentifierHashedHex.
       *
       * If the database is compromised and a bad actor gets access to all the userSecurityKeyHex values, and the bad actor
       * can steal a user's mobile device, the bad actor will not be able to iterate through the userSecurityKeyHex values
       * and test for decryption.
       */
      String userSecurityKeyHexEncrypted = encrypt(toHex(secretKey.getEncoded()), userSecurityKeyHex);
      log("\n\n\n\n########userSecurityKeyHexEncrypted: " + userSecurityKeyHexEncrypted);

      /*
       * Decrypt the userSecurityKeyHexEncrypted to see if it matches the userSecurityKeyHex.
       */
      String userSecurityKeyHexDencrypted = decrypt(toHex(secretKey.getEncoded()), userSecurityKeyHexEncrypted);
      log("\n\n\n\n########userSecurityKeyHexDencrypted: " + userSecurityKeyHexDencrypted + "\n" + userSecurityKeyHex);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * There is no need to URL encode these values because the characters are
       * limited to HEX values.
       */
      String transferData = Constants.OBFUSCATED_IDENTIFIER + "=" + obfuscateIdentifierHashedHex + "&"
              + Constants.USER_SECURITY_KEY_ENCRYPTED + "=" + userSecurityKeyHexEncrypted + "&";

      byte[] transferDataBytes = transferData.getBytes();

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Encrypt the transfer data with the transferKey.
       */
      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[IV_LENGTH];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, transferKey, new IvParameterSpec(ivBytes));

      byte[] transferDataEncryptedBytes = new byte[cipher.getOutputSize(transferDataBytes.length)];

      int transferDataEncryptionPointer = cipher.update(transferDataBytes, 0, transferDataBytes.length, transferDataEncryptedBytes);
      transferDataEncryptionPointer += cipher.doFinal(transferDataEncryptedBytes, transferDataEncryptionPointer);
      log("transferDataEncryptionPointer: " + transferDataEncryptionPointer);

      String transferDataEncryptedHex = toHex(ivBytes) + toHex(transferDataEncryptedBytes);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create a "Message Authentication Code" (MAC) for the transferDataEncryptedHex
       * using the transferKey.  The MAC will insure message integrity.
       */
      Mac macTransferData = Mac.getInstance(MAC_ALGORITHM);
      macTransferData.init(transferKey);
      byte[] transferDataEncryptedHashedBytes = macTransferData.doFinal(transferDataEncryptedHex.getBytes());

      String transferDataEncryptedHashedHex = toHex(transferDataEncryptedHashedBytes);
      log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String urlParameters = Constants.PUBLIC_KEY_UUID_LABEL + "=" + Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID
              + "&" + Constants.TRANSFER_KEY_ENCRYPTED_HEX + "=" + transferKeyEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HEX + "=" + transferDataEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX + "=" + transferDataEncryptedHashedHex;

      return new String[]{urlParameters, toHex(transferKey.getEncoded()), userSecurityKeyHex};

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
            BadPaddingException | ShortBufferException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_CreateUserPublicKey(String userSecurityKeyHex, SharedPreferences sharedPreferences, Context context) {

    log("Entering");

    Editor prefEditor = sharedPreferences.edit();

    try {

      /*
       * Create the transferKey then encrypt it with the mobile app provider public key.
       * This will be packageOne in the HTTP request.
       *
       * The transferKey is used to encrypt the user data that is sent to the mobile app provider
       * Authentication Server.
       */
      KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generator.init(SECRET_KEY_LENGTH);
      Key transferKey = generator.generateKey();

      // --------------------------------------------------------------------------------------------------------------

      PublicKey publicKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(hexStringToByteArray(Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY)));

      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] transferKeyEncryptedBytes = rsaCipher.doFinal(transferKey.getEncoded());

      String transferKeyEncryptedHex = toHex(transferKeyEncryptedBytes);
      log("transferKeyEncryptedHex: " + transferKeyEncryptedHex);

      // --------------------------------------------------------------------------------------------------------------

      String userUuidEncrypted = sharedPreferences.getString(context.getString(R.string.user_uuid_key), context.getString(R.string.empty_string));
      String userUuid = decrypt(userSecurityKeyHex, userUuidEncrypted);
      log("userUuid: " + userUuid);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create the public and private keys for the user.
       */
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_FACTORY_ALGORITHM);

      keyPairGenerator.initialize(PUBLIC_PRIVATE_KEY_LENGTH);
      KeyPair pair = keyPairGenerator.generateKeyPair();

      PublicKey userPublicKey = pair.getPublic();
      String userPublicKeyHex = toHex(userPublicKey.getEncoded());
      log("userPublicKeyHex: " + userPublicKeyHex);

      PrivateKey userPrivateKey = pair.getPrivate();
      String userPrivateKeyHex = toHex(userPrivateKey.getEncoded());
      log("userPrivateKeyHex: " + userPrivateKeyHex);

      // --------------------------------------------------------------------------------------------------------------

      String encryptedPublicKey = encrypt(userSecurityKeyHex, userPublicKeyHex);
      prefEditor.putString(context.getString(R.string.crypto_public_key), encryptedPublicKey);

      String encryptedPrivateKey = encrypt(userSecurityKeyHex, userPrivateKeyHex);
      prefEditor.putString(context.getString(R.string.crypto_private_key), encryptedPrivateKey);

      prefEditor.apply();

      // --------------------------------------------------------------------------------------------------------------

      String transferData = Constants.USER_UUID + "=" + userUuid  + "&"
              + Constants.PUBLIC_KEY_HEX + "=" + userPublicKeyHex + "&";

      byte[] transferDataBytes = transferData.getBytes();

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Encrypt the transfer data with the transferKey.
       */
      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[16];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, transferKey, new IvParameterSpec(ivBytes));

      byte[] transferDataEncryptedBytes = new byte[cipher.getOutputSize(transferDataBytes.length)];

      int transferDataEncryptionPointer = cipher.update(transferDataBytes, 0, transferDataBytes.length, transferDataEncryptedBytes);
      transferDataEncryptionPointer += cipher.doFinal(transferDataEncryptedBytes, transferDataEncryptionPointer);
      log("transferDataEncryptionPointer: " + transferDataEncryptionPointer);

      String transferDataEncryptedHex = toHex(ivBytes) + toHex(transferDataEncryptedBytes);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create a "Message Authentication Code" (MAC) for the transferDataEncryptedHex
       * using the transferKey.  The MAC will insure message integrity.
       */
      Mac macTransferData = Mac.getInstance(MAC_ALGORITHM);
      macTransferData.init(transferKey);
      byte[] transferDataEncryptedHashedBytes = macTransferData.doFinal(transferDataEncryptedHex.getBytes());

      String transferDataEncryptedHashedHex = toHex(transferDataEncryptedHashedBytes);
      log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String urlParameters = Constants.PUBLIC_KEY_UUID_LABEL + "=" + Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID
              + "&" + Constants.TRANSFER_KEY_ENCRYPTED_HEX + "=" + transferKeyEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HEX + "=" + transferDataEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX + "=" + transferDataEncryptedHashedHex;

      return new String[]{urlParameters, toHex(transferKey.getEncoded())};

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException |
            BadPaddingException | InvalidAlgorithmParameterException | InvalidKeySpecException | ShortBufferException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

    // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_RetrieveTransactionUuid(String userUuid, PrivateKey privateKey, String publicKeyUuid, String publicKeyHex) {

    log("Entering");

    log("userUuid::" + userUuid);
    log("privateKey::" + privateKey);
    log("publicKeyUuid::" + publicKeyUuid);
    log("publicKeyHex::" + publicKeyHex);

    String transactionUuid = System.currentTimeMillis() + "-" + UUID.randomUUID().toString();

    try {

      /*
       * Create the transferKey then encrypt it with the mobile app provider public key.
       * This will be packageOne in the HTTP request.
       *
       * The transferKey is used to encrypt the user data that is sent to the mobile app
       * provider Authentication Server.
       */
      KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generator.init(SECRET_KEY_LENGTH);
      Key transferKey = generator.generateKey();

      // --------------------------------------------------------------------------------------------------------------

      PublicKey publicKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(hexStringToByteArray(publicKeyHex)));

      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] transferKeyEncryptedBytes = rsaCipher.doFinal(transferKey.getEncoded());

      String transferKeyEncryptedHex = toHex(transferKeyEncryptedBytes);
      log("transferKeyEncryptedHex: " + transferKeyEncryptedHex);

      // --------------------------------------------------------------------------------------------------------------

      String transferData = Constants.USER_UUID + "=" + userUuid + "&"
              + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
              + Constants.TRANSACTION_UUID_SIGNED + "="
              + CryptoUtilities.generateSignedHex(transactionUuid, privateKey) + "&";

      log("transferData: " + transferData);

      byte[] transferDataBytes = transferData.getBytes();

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Encrypt the transfer data with the transferKey.
       */
      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[IV_LENGTH];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, transferKey, new IvParameterSpec(ivBytes));

      byte[] transferDataEncryptedBytes = new byte[cipher.getOutputSize(transferDataBytes.length)];

      int transferDataEncryptionPointer = cipher.update(transferDataBytes, 0, transferDataBytes.length, transferDataEncryptedBytes);
      transferDataEncryptionPointer += cipher.doFinal(transferDataEncryptedBytes, transferDataEncryptionPointer);
      log("transferDataEncryptionPointer: " + transferDataEncryptionPointer);

      String transferDataEncryptedHex = toHex(ivBytes) + toHex(transferDataEncryptedBytes);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create a "Message Authentication Code" (MAC) for the transferDataEncryptedHex
       * using the transferKey.  The MAC will insure message integrity.
       */
      Mac macTransferData = Mac.getInstance(MAC_ALGORITHM);
      macTransferData.init(transferKey);
      byte[] transferDataEncryptedHashedBytes = macTransferData.doFinal(transferDataEncryptedHex.getBytes());

      String transferDataEncryptedHashedHex = toHex(transferDataEncryptedHashedBytes);
      log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String urlParameters = Constants.PUBLIC_KEY_UUID_LABEL + "=" + publicKeyUuid
              + "&" + Constants.TRANSFER_KEY_ENCRYPTED_HEX + "=" + transferKeyEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HEX + "=" + transferDataEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX + "=" + transferDataEncryptedHashedHex;

      return new String[]{urlParameters, toHex(transferKey.getEncoded())};

    } catch (Exception e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_UpdateUser(String userSecurityKeyHex, String transactionUuid, SharedPreferences sharedPreferences, Context context) {

    log("Entering");

    try {

      /*
       * Create the transferKey then encrypt it with the mobile app provider public key.
       * This will be packageOne in the HTTP request.
       *
       * The transferKey is used to encrypt the user data that is sent to the mobile app provider
       * Authentication Server.
       */
      KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generator.init(SECRET_KEY_LENGTH);
      Key transferKey = generator.generateKey();

      // --------------------------------------------------------------------------------------------------------------

      PublicKey publicKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(hexStringToByteArray(Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY)));

      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] transferKeyEncryptedBytes = rsaCipher.doFinal(transferKey.getEncoded());

      String transferKeyEncryptedHex = toHex(transferKeyEncryptedBytes);
      log("transferKeyEncryptedHex: " + transferKeyEncryptedHex);

      // --------------------------------------------------------------------------------------------------------------

      String userUuidEncrypted = sharedPreferences.getString(context.getString(R.string.user_uuid_key), context.getString(R.string.empty_string));
      String userUuid = decrypt(userSecurityKeyHex, userUuidEncrypted);
      log("userUuid: " + userUuid);

      String firebaseDeviceIdEncrypted = sharedPreferences.getString(context.getString(R.string.firebase_device_id), context.getString(R.string.empty_string));
      String firebaseDeviceId = CryptoUtilities.decrypt(userSecurityKeyHex, firebaseDeviceIdEncrypted);
      log("firebaseDeviceId: " + firebaseDeviceId);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Use the userSecurityKey to decrypt the privateKey.
       */
      String encryptedPrivateKeyHex = sharedPreferences.getString(context.getString(R.string.crypto_private_key), context.getString(R.string.empty_string));
      log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

      PrivateKey privateKey = retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

      // --------------------------------------------------------------------------------------------------------------

      String screenNameValueEncrypted = sharedPreferences.getString(context.getString(R.string.screen_name_key), context.getString(R.string.empty_string));
      String screenNameValue = CryptoUtilities.decrypt(userSecurityKeyHex, screenNameValueEncrypted);

      String emailValueEncrypted = sharedPreferences.getString(context.getString(R.string.email_key), context.getString(R.string.empty_string));
      String emailValue = CryptoUtilities.decrypt(userSecurityKeyHex, emailValueEncrypted);

      // ----------------------------------------------------------------------------------------------------------------

      String firstNameValueEncrypted = sharedPreferences.getString(context.getString(R.string.first_name_key), context.getString(R.string.empty_string));
      String firstNameValue = CryptoUtilities.decrypt(userSecurityKeyHex, firstNameValueEncrypted);

      String lastNameValueEncrypted = sharedPreferences.getString(context.getString(R.string.last_name_key), context.getString(R.string.empty_string));
      String lastNameValue = CryptoUtilities.decrypt(userSecurityKeyHex, lastNameValueEncrypted);

      String phoneValueEncrypted = sharedPreferences.getString(context.getString(R.string.phone_key), context.getString(R.string.empty_string));
      String phoneValue = CryptoUtilities.decrypt(userSecurityKeyHex, phoneValueEncrypted);

      // ----------------------------------------------------------------------------------------------------------------

      String legalAddressLineOneValueEncrypted = sharedPreferences.getString(context.getString(R.string.legal_address_line_one_key), context.getString(R.string.empty_string));
      String legalAddressLineOneValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalAddressLineOneValueEncrypted);

      String legalAddressLineTwoValueEncrypted = sharedPreferences.getString(context.getString(R.string.legal_address_line_two_key), context.getString(R.string.empty_string));
      String legalAddressLineTwoValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalAddressLineTwoValueEncrypted);

      String legalCityValueEncrypted = sharedPreferences.getString(context.getString(R.string.legal_address_city_key), context.getString(R.string.empty_string));
      String legalCityValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalCityValueEncrypted);

      String legalStateValueEncrypted = sharedPreferences.getString(context.getString(R.string.legal_address_state_key), context.getString(R.string.empty_string));
      String legalStateValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalStateValueEncrypted);

      String legalPostalCodeValueEncrypted = sharedPreferences.getString(context.getString(R.string.legal_address_postal_code_key), context.getString(R.string.empty_string));
      String legalPostalCodeValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalPostalCodeValueEncrypted);

      String legalCountryValuePrefEncrypted = sharedPreferences.getString(context.getString(R.string.legal_address_country_key), context.getString(R.string.empty_string));
      String legalCountryValuePref = CryptoUtilities.decrypt(userSecurityKeyHex, legalCountryValuePrefEncrypted);

      String transferData = Constants.SCREEN_NAME + "=" + screenNameValue + "&"
                          + Constants.EMAIL + "=" + emailValue + "&"
                          + Constants.PHONE + "=" + phoneValue + "&"
                          + Constants.FIRST_NAME + "=" + firstNameValue + "&"
                          + Constants.LAST_NAME + "=" + lastNameValue + "&"
                          + Constants.USER_UUID + "=" + userUuid + "&"
                          + Constants.FIRE_BASE_DEVICE_ID + "=" + firebaseDeviceId + "&"
                          + Constants.TRANSACTION_UUID + "=" + transactionUuid + "&"
                          + Constants.TRANSACTION_UUID_SIGNED + "=" + CryptoUtilities.generateSignedHex(transactionUuid, privateKey) + "&"

                          + Constants.LEGAL_ADDRESS_LINE_ONE + "=" + legalAddressLineOneValue + "&"
                          + Constants.LEGAL_ADDRESS_LINE_TWO + "=" + legalAddressLineTwoValue + "&"
                          + Constants.LEGAL_ADDRESS_CITY + "=" + legalCityValue + "&"
                          + Constants.LEGAL_ADDRESS_STATE + "=" + legalStateValue + "&"
                          + Constants.LEGAL_ADDRESS_POSTAL_CODE + "=" + legalPostalCodeValue + "&"
                          + Constants.LEGAL_ADDRESS_COUNTRY + "=" + legalCountryValuePref + "&";

      byte[] transferDataBytes = transferData.getBytes();

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Encrypt the user data with the transferKey.
       */
      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[IV_LENGTH];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, transferKey, new IvParameterSpec(ivBytes));

      byte[] transferDataEncryptedBytes = new byte[cipher.getOutputSize(transferDataBytes.length)];

      int transferDataEncryptionPointer = cipher.update(transferDataBytes, 0, transferDataBytes.length, transferDataEncryptedBytes);
      transferDataEncryptionPointer += cipher.doFinal(transferDataEncryptedBytes, transferDataEncryptionPointer);
      log("transferDataEncryptionPointer: " + transferDataEncryptionPointer);

      String transferDataEncryptedHex = toHex(ivBytes) + toHex(transferDataEncryptedBytes);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create a "Message Authentication Code" (MAC) for the transferDataEncryptedHex
       * using the transferKey.  The MAC will insure message integrity.
       */
      Mac macTransferData = Mac.getInstance(MAC_ALGORITHM);
      macTransferData.init(transferKey);
      byte[] transferDataEncryptedHashedBytes = macTransferData.doFinal(transferDataEncryptedHex.getBytes());

      String transferDataEncryptedHashedHex = toHex(transferDataEncryptedHashedBytes);
      log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String urlParameters = Constants.PUBLIC_KEY_UUID_LABEL + "=" + Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID
              + "&" + Constants.TRANSFER_KEY_ENCRYPTED_HEX + "=" + transferKeyEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HEX + "=" + transferDataEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX + "=" + transferDataEncryptedHashedHex;

      return new String[]{urlParameters, toHex(transferKey.getEncoded())};

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException |
            BadPaddingException | ShortBufferException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_MobileApplicationSignOn(String passwordValue, SharedPreferences sharedPreferences, Context context) {

    log("Entering");

    try {

      /*
       * Create the transferKey then encrypt it with the mobile app provider public key.
       * This will be packageOne in the HTTP request.
       *
       * The transferKey is used to encrypt the user data that is sent to the mobile app provider
       * Authentication Server.
       */
      KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generator.init(SECRET_KEY_LENGTH);
      Key transferKey = generator.generateKey();

      // --------------------------------------------------------------------------------------------------------------

      PublicKey publicKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(hexStringToByteArray(Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY)));

      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] transferKeyEncryptedBytes = rsaCipher.doFinal(transferKey.getEncoded());

      String transferKeyEncryptedHex = toHex(transferKeyEncryptedBytes);
      log("transferKeyEncryptedHex: " + transferKeyEncryptedHex);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Recreate the secretKey starting with the password based encryption key.
       *
       * The secretKey is never stored on the user's mobile devise.
       * The secretKey is recreated by the user using his/her PIN.
       *
       * The secretKey is used to confirm the user's identity with the mobile app provider
       * Authentication Server.
       */
      char[] passwordValueBytes = passwordValue.toCharArray();

      String saltHex = sharedPreferences.getString(context.getString(R.string.crypto_salt_key), context.getString(R.string.empty_string));
      log("saltHex: " + saltHex);

      byte salt[] = hexStringToByteArray(saltHex);

      /*
       *  TODO:  Update to Argon2 when it become available in Android.
       */

      long begTime = System.currentTimeMillis();

      /*
       * Reference:
       * http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
       */
      SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBE_KEY_FACTORY_ALGORITHM);
      PBEKeySpec pbeKeySpec = new PBEKeySpec(passwordValueBytes, salt, PBE_ITERATION_COUNT, PBE_KEY_LENGTH);
      Key tempSecretKey = secretKeyFactory.generateSecret(pbeKeySpec);
      Key secretKey = new SecretKeySpec(tempSecretKey.getEncoded(), SECRET_KEY_ALGORITHM);

      log("secretKey: " + toHex(secretKey.getEncoded()));

      long endTime = System.currentTimeMillis();

      log("\n\n\n\n####pbeKeySpec genTime: " + (endTime - begTime));

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Get the unhashed version of the obfuscatedIdentifier which is stored on the user's
       * mobile device.  When the obfuscatedIdentifier is hashed with the sceretKey it is used
       * as an obfuscated identifier to obtain the user's userSecurityKey (i.e., the
       * key that is used to encrypt/decrypt user data).
       *
       * The userSecurityKey is not stored on the user's mobile device; it is stored
       * on the mobile app provider Authentication Server and is accessible only
       * through the hashed  obfuscatedIdentifier.  There is no association in the mobile app
       * provider data structures between user information and the user's userSecurityKey.
       */
      String obfuscatedIdentifier = sharedPreferences.getString(context.getString(R.string.obfuscated_identifier_key), context.getString(R.string.empty_string));
      log("obfuscatedIdentifier: " + obfuscatedIdentifier);

      /*
       * Hash the userIdentifier.
       */
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(secretKey);
      byte[] userIdentifierHashedBytes = mac.doFinal(obfuscatedIdentifier.getBytes());

      String userIdentifierHashedHex = toHex(userIdentifierHashedBytes);
      log("userIdentifierHashedHex: " + userIdentifierHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String transferData = Constants.OBFUSCATED_IDENTIFIER + "=" + userIdentifierHashedHex + "&";

      byte[] transferDataBytes = transferData.getBytes();

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Encrypt the user data with the transferKey.
       */
      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[IV_LENGTH];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, transferKey, new IvParameterSpec(ivBytes));

      byte[] transferDataEncryptedBytes = new byte[cipher.getOutputSize(transferDataBytes.length)];

      int transferDataEncryptionPointer = cipher.update(transferDataBytes, 0, transferDataBytes.length, transferDataEncryptedBytes);
      transferDataEncryptionPointer += cipher.doFinal(transferDataEncryptedBytes, transferDataEncryptionPointer);
      log("transferDataEncryptionPointer: " + transferDataEncryptionPointer);

      String transferDataEncryptedHex = toHex(ivBytes) + toHex(transferDataEncryptedBytes);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create a "Message Authentication Code" (MAC) for the transferDataEncryptedHex
       * using the transferKey.  The MAC will insure message integrity.
       */
      Mac macTransferData = Mac.getInstance(MAC_ALGORITHM);
      macTransferData.init(transferKey);
      byte[] transferDataEncryptedHashedBytes = macTransferData.doFinal(transferDataEncryptedHex.getBytes());

      String transferDataEncryptedHashedHex = toHex(transferDataEncryptedHashedBytes);
      log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String urlParameters = Constants.PUBLIC_KEY_UUID_LABEL + "=" + Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID
              + "&" + Constants.TRANSFER_KEY_ENCRYPTED_HEX + "=" + transferKeyEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HEX + "=" + transferDataEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX + "=" + transferDataEncryptedHashedHex;

      /*
       * The urlParameters will be sent to the mobile app provider Authentication  server
       * to initiate  the sign on process.  The transferKey is used by the mobile app
       * provider Authentication server  to wrap the userSecurityKey.  The transferKey
       * will be returned to the Activate Intent so that it can be used to unwrap the
       * userSecurityKey when it is returned by the mobile app provider Authentication server.
       */

      return new String[]{urlParameters, toHex(transferKey.getEncoded()), toHex(secretKey.getEncoded())};

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException |
            InvalidAlgorithmParameterException | BadPaddingException | InvalidKeySpecException | ShortBufferException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_RetrieveCredentialMetaData(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_CreateCredential(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_CredentialSignOn(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_UpdateFirebaseDeviceId(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_DeleteCredential(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_RetrieveUnsignedDistributedLedger(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_ReturnSignedDistributedLedger(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_SendFunds(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_ReceiveFunds(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String[] generateParams_AcceptFunds(String transferData, String publicKeyUuid, String publicKeyHex) {
    return generateParams_GeneralProcess(transferData, publicKeyUuid, publicKeyHex);
  }

  // ------------------------------------------------------------------------------------------------------------------

  private static String[] generateParams_GeneralProcess(String transferData, String publicKeyUuid, String publicKeyHex) {

    log("Entering");

    log("transferData::" + transferData);
    log("publicKeyUuid::" + publicKeyUuid);
    log("publicKeyHex::" + publicKeyHex);

    try {

      /*
       * Create the transferKey then encrypt it with the mobile app provider public key.
       * This will be packageOne in the HTTP request.
       *
       * The transferKey is used to encrypt the user data that is sent to the mobile app
       * provider Authentication Server.
       */
      KeyGenerator generator = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
      generator.init(SECRET_KEY_LENGTH);
      Key transferKey = generator.generateKey();

      // --------------------------------------------------------------------------------------------------------------

      PublicKey publicKey = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(hexStringToByteArray(publicKeyHex)));

      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] transferKeyEncryptedBytes = rsaCipher.doFinal(transferKey.getEncoded());

      String transferKeyEncryptedHex = toHex(transferKeyEncryptedBytes);
      log("transferKeyEncryptedHex: " + transferKeyEncryptedHex);

      // --------------------------------------------------------------------------------------------------------------

      byte[] transferDataBytes = transferData.getBytes();

      /*
       * Encrypt the transfer data with the transferKey.
       */
      SecureRandom random = new SecureRandom();
      byte ivBytes[] = new byte[IV_LENGTH];
      random.nextBytes(ivBytes);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, transferKey, new IvParameterSpec(ivBytes));

      byte[] transferDataEncryptedBytes = new byte[cipher.getOutputSize(transferDataBytes.length)];

      int transferDataEncryptionPointer = cipher.update(transferDataBytes, 0, transferDataBytes.length, transferDataEncryptedBytes);
      transferDataEncryptionPointer += cipher.doFinal(transferDataEncryptedBytes, transferDataEncryptionPointer);
      log("transferDataEncryptionPointer: " + transferDataEncryptionPointer);

      String transferDataEncryptedHex = toHex(ivBytes) + toHex(transferDataEncryptedBytes);

      // --------------------------------------------------------------------------------------------------------------

      /*
       * Create a "Message Authentication Code" (MAC) for the transferDataEncryptedHex
       * using the transferKey.  The MAC will insure message integrity.
       */
      Mac macTransferData = Mac.getInstance(MAC_ALGORITHM);
      macTransferData.init(transferKey);
      byte[] transferDataEncryptedHashedBytes = macTransferData.doFinal(transferDataEncryptedHex.getBytes());

      String transferDataEncryptedHashedHex = toHex(transferDataEncryptedHashedBytes);
      log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

      // --------------------------------------------------------------------------------------------------------------

      String urlParameters = Constants.PUBLIC_KEY_UUID_LABEL + "=" + publicKeyUuid
              + "&" + Constants.TRANSFER_KEY_ENCRYPTED_HEX + "=" + transferKeyEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HEX + "=" + transferDataEncryptedHex
              + "&" + Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX + "=" + transferDataEncryptedHashedHex;

      return new String[]{urlParameters, toHex(transferKey.getEncoded())};

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
            IllegalBlockSizeException | ShortBufferException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
    }

    return null;
  }

  // ------------------------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------------------------

  public static String decryptResponseString (String responseString, String transferKeyHex, Context context) {

    log("Entering");

    if (responseString.contains(Constants.TRANSFER_DATA_ENCRYPTED_HEX) && responseString.contains(Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX)) {

      try {
        Key transferKey = new SecretKeySpec(CryptoUtilities.hexStringToByteArray(transferKeyHex), "AES");

        /*
         * The TRANSFER_DATA_ENCRYPTED_HEX HTTP request package contains the transfer data
         * encrypted with the transferKey.
         */
        String transferDataEncryptedHex = Utilities.parseNameValuePairs(responseString, Constants.TRANSFER_DATA_ENCRYPTED_HEX);
        log("transferDataEncryptedHex::" + transferDataEncryptedHex + "::");

        // --------------------------------------------------------------------------------------------------------------

        /*
         * Hash the transferDataEncryptedHex using the transferKey.
         */
        Mac macCredentialData = Mac.getInstance("HmacSHA256");
        macCredentialData.init(transferKey);
        byte[] transferDataEncryptedHashedBytesTest = macCredentialData.doFinal(transferDataEncryptedHex.getBytes());

        String transferDataEncryptedHashedHexTest = CryptoUtilities.toHex(transferDataEncryptedHashedBytesTest);
        log("transferDataEncryptedHashedHexTest: " + transferDataEncryptedHashedHexTest);

        String transferDataEncryptedHashedHex = Utilities.parseNameValuePairs(responseString, Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX);
        log("transferDataEncryptedHashedHex: " + transferDataEncryptedHashedHex);

        /*
         * Test the hashed values to determine the integrity of the message.  If the
         * hashed values are equal continue with the process; else return a message.
         */
        if (transferDataEncryptedHashedHex.equals(transferDataEncryptedHashedHexTest)) {

          String transferDataDecrypted = CryptoUtilities.decrypt(transferKeyHex, transferDataEncryptedHex);
          log("transferDataDecrypted: " + transferDataDecrypted + "\n\n");

          responseString = transferDataDecrypted;

        } else {
          responseString = context.getString(R.string.message_integrity_compromised);
        }

      } catch (Exception e) {
        log("Exception: " + e + "\n\n");
        e.printStackTrace();
        responseString = context.getString(R.string.problem_retrieving_response);
      }

      return responseString.trim();

    } else {
      return context.getString(R.string.problem_retrieving_response);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String digest(String string) {

    log("Entering");

    try {
      byte[] encrypt = string.getBytes();

      MessageDigest messageDigest = MessageDigest.getInstance(SECURE_HASH_ALGORITHM);
      messageDigest.update(encrypt);

      byte[] digest = messageDigest.digest();

      return toHex(digest);

    } catch (Exception e) {
      e.printStackTrace();
      log("exception::" + e.getMessage());
      return null;
    }
  }
}










