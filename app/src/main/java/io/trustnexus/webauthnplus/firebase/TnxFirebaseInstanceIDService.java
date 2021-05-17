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

package io.trustnexus.webauthnplus.firebase;

import android.util.Log;

import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.FirebaseInstanceIdService;
import io.trustnexus.webauthnplus.util.Constants;

public class TnxFirebaseInstanceIDService extends FirebaseInstanceIdService {

  @Override
  public void onTokenRefresh() {
    String refreshedToken = FirebaseInstanceId.getInstance().getToken();
    Log.d(Constants.LOG_PREFIX, "Refreshed token: " + refreshedToken);
    sendRegistrationToServer(refreshedToken);
  }

  // ------------------------------------------------------------------------------------------------------------------

  /*
   * In the ActivatePassword activity a check of the token is made every time the user signs on.
   * If the token has been updated, a server call is made to update the value.
   */
  private void sendRegistrationToServer(String token) {
  }
}

