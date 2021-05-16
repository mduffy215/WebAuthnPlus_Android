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

package com.tnxsecure.webauthnplus.firebase;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;
import com.tnxsecure.webauthnplus.ActivatePassword;
import com.tnxsecure.webauthnplus.Credentials;
import com.tnxsecure.webauthnplus.WebAuthnPlus;
import com.tnxsecure.webauthnplus.R;
import com.tnxsecure.webauthnplus.distributedledger.Signature;
import com.tnxsecure.webauthnplus.fundstransfer.ConfirmFunds;
import com.tnxsecure.webauthnplus.util.Constants;

public class TnxFirebaseMessagingService extends FirebaseMessagingService {

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
   * If a Firbase notification comes in and the app is closed or not in focus, the notification is sent to the extras
   * Bundle of the main activity, ActivatePassword.  If a Firbase notification comes in and the app is open, the notification
   * is sent to TnxFirebaseMessagingService.onMessageReceived(...).
   */
  public void onMessageReceived(RemoteMessage remoteMessage) {

    log("################Message From: " + remoteMessage.getFrom());

    String firebaseMsgType = "";

    if (remoteMessage.getData().size() > 0) {

      log("################################ Message data: " + remoteMessage.getData());

      firebaseMsgType = remoteMessage.getData().get(Constants.FIREBASE_MSG_TYPE_KEY);
      log("################################ firebaseMsgType: " + firebaseMsgType);

      ((WebAuthnPlus)getApplication()).setFirebaseDataEncryptedHex(remoteMessage.getData().get(Constants.TRANSFER_DATA_ENCRYPTED_HEX));
      log("################################ transferDataEncryptedHex: " + remoteMessage.getData().get(Constants.TRANSFER_DATA_ENCRYPTED_HEX));

      ((WebAuthnPlus)getApplication()).setFirebaseDataEncryptedHashedHex(remoteMessage.getData().get(Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX));
      log("################################ transferDataEncryptedHashedHex: " + remoteMessage.getData().get(Constants.TRANSFER_DATA_ENCRYPTED_HASHED_HEX));

      log("################################  " + ((WebAuthnPlus)getApplication()).getCurrentActivity());
    }

    // ----------------------------------------------------------------------------------------------------------------

    long lastInteraction = ((WebAuthnPlus)getApplication()).getLastInteraction();

    long currentTimeMillis = System.currentTimeMillis();

    long timeDifferential = currentTimeMillis - lastInteraction;
    log("################ timeDifferential: " + currentTimeMillis + " - " + lastInteraction + " = " + timeDifferential);

    Uri notification = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
    Ringtone ringtone = RingtoneManager.getRingtone(getApplicationContext(), notification);
    ringtone.play();

    if (timeDifferential < Constants.MAX_IDLE_TIME) {
      switch (firebaseMsgType) {
        case Constants.FIREBASE_MSG_TYPE_CREATE_CREDENTIAL:
        case Constants.FIREBASE_MSG_TYPE_SIGN_ON:

          Intent credentials = new Intent(this, Credentials.class);
          credentials.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
          startActivity(credentials);

          break;
        case Constants.FIREBASE_MSG_TYPE_CONFIRM_FUNDS_TRANSFER:

          Intent confirmFunds = new Intent(this, ConfirmFunds.class);
          confirmFunds.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
          startActivity(confirmFunds);

          break;
        case Constants.FIREBASE_MSG_TYPE_SIGN_DISTRIBUTED_LEDGER:

          Intent dltSignature = new Intent(this, Signature.class);
          dltSignature.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
          startActivity(dltSignature);
          break;
      }

    } else {
      Intent activate = new Intent(this, ActivatePassword.class);
      activate.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
      startActivity(activate);
    }
  }
  
  // ------------------------------------------------------------------------------------------------------------------
  
  private void sendNotification(String messageTitle, String messageBody) {

    log("################messageTitle: " + messageTitle);
    log("################messageBody: " + messageBody);

    Intent intent;

    if (((WebAuthnPlus)getApplication()).getSignOnSuccessful()) {
      intent = new Intent(this, Credentials.class);
    } else {
      intent = new Intent(this, ActivatePassword.class);
    }

    intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
    PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_ONE_SHOT);

    Uri defaultSoundUri= RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
    NotificationCompat.Builder notificationBuilder = new NotificationCompat.Builder(this)
            .setSmallIcon(R.mipmap.ic_tnx_c)
            .setContentTitle(messageTitle)
            .setContentText(messageBody)
            .setAutoCancel(true)
            .setSound(defaultSoundUri)
            .setContentIntent(pendingIntent);

    NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

    if (notificationManager != null) {
      notificationManager.cancel(Constants.TNX_NOTIFICATION);
      notificationManager.notify(Constants.TNX_NOTIFICATION, notificationBuilder.build());
    }
  }
}

