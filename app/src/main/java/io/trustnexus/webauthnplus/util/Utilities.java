package io.trustnexus.webauthnplus.util;

import android.text.TextUtils;
import android.util.Log;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashSet;

public class Utilities {

  private static HashSet<String> sensitiveWordsFour;
  private static HashSet<String> sensitiveWordsThree;

  static {

    sensitiveWordsFour = new HashSet<>();
    Collections.addAll(sensitiveWordsFour, Constants.SENSITIVE_WORDS_FOUR);

    sensitiveWordsThree = new HashSet<>();
    Collections.addAll(sensitiveWordsThree, Constants.SENSITIVE_WORDS_THREE);
  }

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

  public static String generateVerificationCodeTwelve() {

    boolean sensitive = true;
    StringBuilder verificationCode = new StringBuilder();
    String verificationCodeSegment = "";

    for (int i = 0; i < 3; i++) {

      while (sensitive) {

        int characterOne = (int) Math.floor(Constants.CHARACTER_ARRAY.length * Math.random());
        int characterTwo = (int) Math.floor(Constants.CHARACTER_ARRAY.length * Math.random());
        int characterThree = (int) Math.floor(Constants.CHARACTER_ARRAY.length * Math.random());
        int characterFour = (int) Math.floor(Constants.CHARACTER_ARRAY.length * Math.random());

        verificationCodeSegment = "" + Constants.CHARACTER_ARRAY[characterOne] + Constants.CHARACTER_ARRAY[characterTwo] + Constants.CHARACTER_ARRAY[characterThree] + Constants.CHARACTER_ARRAY[characterFour];

        sensitive = sensitiveWordsFour.contains(verificationCodeSegment);
      }

      sensitive = true;
      verificationCode.append(verificationCodeSegment).append(" ");
    }

    return verificationCode.toString().trim();
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String generateVerificationCode() {

    boolean sensitive = true;
    String verificationCode = null;

    double mathRandom = 1000 * Math.random();

    while (mathRandom < 100) {
      mathRandom = mathRandom * 10;
    }

    while (sensitive) {

      int characterOne = (int) Math.floor(Constants.CHARACTER_ARRAY.length * Math.random());
      int characterTwo = (int) Math.floor(Constants.CHARACTER_ARRAY.length * Math.random());
      int characterThree = (int) Math.floor(Constants.CHARACTER_ARRAY.length * Math.random());

      verificationCode = "" + Constants.CHARACTER_ARRAY[characterOne] + Constants.CHARACTER_ARRAY[characterTwo] + Constants.CHARACTER_ARRAY[characterThree];

      sensitive = sensitiveWordsThree.contains(verificationCode);
    }

    verificationCode += " " + (int) Math.floor(mathRandom);

    return verificationCode;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String parseNameValuePairs(String parseString, String name) {

    int begIndex = parseString.indexOf(name);
    int endIndex;

    if (begIndex != -1) {

      begIndex = parseString.indexOf("=", begIndex);

      if (begIndex != -1) {

        begIndex ++;
        endIndex = parseString.indexOf("&", begIndex);

        if (endIndex != -1) {
          return parseString.substring(begIndex, endIndex).trim();
        } else {
          return parseString.substring(begIndex).trim();
        }

      } else {
        return "";
      }

    } else {
      return "";
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String parseJsonNameValuePairs(String parseString, String name) {

    int begIndex;
    int endIndex;

    begIndex = parseString.indexOf(name);

    if (begIndex != -1) {

      begIndex = parseString.indexOf(":", begIndex);

      if (begIndex != -1) {

        begIndex ++;
        begIndex ++;
        endIndex = parseString.indexOf("\",", begIndex);

        if (endIndex != -1) {
          return parseString.substring(begIndex, endIndex).trim();
        } else {
          return "";
        }

      } else {
        return "";
      }

    } else {
      return "";
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  /*
   * https://stackoverflow.com/questions/6119722/how-to-check-edittexts-text-is-email-address-or-not
   */
  public static boolean isEmailValid(CharSequence email) {
    return !TextUtils.isEmpty(email) && android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches();
  }

  // ------------------------------------------------------------------------------------------------------------------

  public static String generateIsoTimestamp(long timeMillis) {

    String isoTimeStamp = new Timestamp(timeMillis).toString();

    isoTimeStamp = isoTimeStamp.substring(0, 10) + "T" + isoTimeStamp.substring(11) + "0000";
    isoTimeStamp = isoTimeStamp.substring(0, isoTimeStamp.lastIndexOf(".") + 4) + Constants.ZULU_ADJUSTMENT;

    return isoTimeStamp;
  }
}
