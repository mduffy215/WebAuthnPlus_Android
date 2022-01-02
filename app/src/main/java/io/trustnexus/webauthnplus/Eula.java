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

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.preference.PreferenceManager;
import android.widget.TextView;

import io.trustnexus.webauthnplus.R;

/*
 * Thx to Donn Felker
 * http://www.donnfelker.com/android-a-simple-eula-for-your-android-apps/
 */
public class Eula {

  private Activity mActivity;

  Eula(Activity context) {
    mActivity = context;
  }

  // ------------------------------------------------------------------------------------------------------------------

  private PackageInfo getPackageInfo() {
    PackageInfo pi = null;
    try {
      pi = mActivity.getPackageManager().getPackageInfo(mActivity.getPackageName(), PackageManager.GET_ACTIVITIES);
    } catch (PackageManager.NameNotFoundException e) {
      e.printStackTrace();
    }
    return pi;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public void show() {
    PackageInfo versionInfo = getPackageInfo();

    // the eulaKey changes every time you increment the version number in the AndroidManifest.xml
    String EULA_PREFIX = "eula_";
    final String eulaKey = EULA_PREFIX + versionInfo.versionCode;
    final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(mActivity);
    boolean hasBeenShown = prefs.getBoolean(eulaKey, false);
    if (!hasBeenShown) {

      // Show the Eula
      String title = mActivity.getString(R.string.app_name_tnx) + " " + mActivity.getString(R.string.eula_header) + " v" + versionInfo.versionName;

      //Includes the updates as well so users know what changed.
      String message = mActivity.getText(R.string.eula_update) + "\n" + mActivity.getText(R.string.eula);

      AlertDialog.Builder builder = new AlertDialog.Builder(mActivity)
              .setTitle(title)
              .setMessage(message)
              .setPositiveButton(mActivity.getText(R.string.accept), new Dialog.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialogInterface, int i) {
                  // Mark this version as read.
                  SharedPreferences.Editor editor = prefs.edit();
                  editor.putBoolean(eulaKey, true);
                  editor.apply();
                  dialogInterface.dismiss();
                }
              })
              .setNegativeButton(android.R.string.cancel, new Dialog.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialog, int which) {
                  // Close the activity as they have declined the EULA
                  mActivity.finish();
                }

              });

      AlertDialog alert = builder.create();
      alert.show();

      TextView msgTxt = (TextView) alert.findViewById(android.R.id.message);
      msgTxt.setTextSize(12);
    }
  }
}







