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

package com.tnxsecure.webauthnplus;

import android.app.Activity;
import android.content.Intent;
import android.util.Log;

import com.tnxsecure.webauthnplus.util.Constants;

public class ActivityBase extends Activity {

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

  /*
   * After hours of research and testing, I came to the conclusion that the entire code block
   * in an activity's onClick event must be contained within a conditional "if block" that only
   * allows the code to run if the max idle time has not been exceeded.  If you attempt to
   * override the dispatchTouchEvent() method or the onResume() method or the onPause() method,
   * etc., the code in the on click event will still run.
   *
   * Both the following "solutions" fail:
   *
   * http://stackoverflow.com/questions/11496083/creating-and-handling-an-app-timeout-in-android
   * http://stackoverflow.com/questions/576600/lock-android-app-after-a-certain-amount-of-idle-time
   */

  protected boolean checkMaxIdleTimeExceeded() {

    long lastInteraction = ((WebAuthnPlus)getApplication()).getLastInteraction();

    long currentTimeMillis = System.currentTimeMillis();

    long timeDifferential = currentTimeMillis - lastInteraction;
    log("################ timeDifferential: " + currentTimeMillis + " - " + lastInteraction + " = " + timeDifferential);

    if (timeDifferential > Constants.MAX_IDLE_TIME) {

      ((WebAuthnPlus)getApplication()).setExitValues();

      ((WebAuthnPlus)getApplication()).setLastInteraction(Constants.MAX_IDLE_TIME);

      Intent activate = new Intent(this, ActivatePassword.class);
      activate.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
      startActivity(activate);
      finishAffinity();

      return true;

    } else {

      ((WebAuthnPlus)getApplication()).setLastInteraction(currentTimeMillis);

      return false;
    }
  }
}







