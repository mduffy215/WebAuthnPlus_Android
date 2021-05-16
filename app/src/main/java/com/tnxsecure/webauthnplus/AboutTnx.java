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

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.FrameLayout;
import android.widget.ImageView;

public class AboutTnx extends ActivityBase {

  private boolean signOnSuccessful;

  @Override
  protected void onCreate(Bundle savedInstanceState) {

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_about_tnx);

    // ----------------------------------------------------------------------------------------------------------------

    ImageView applicationIcon = (ImageView) findViewById(android.R.id.home);
    FrameLayout.LayoutParams applicationIconLayoutParams = (FrameLayout.LayoutParams) applicationIcon.getLayoutParams();
    applicationIconLayoutParams.topMargin = 0;
    applicationIconLayoutParams.bottomMargin = 0;
    applicationIcon.setLayoutParams(applicationIconLayoutParams);

    // ----------------------------------------------------------------------------------------------------------------

    final SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

    signOnSuccessful = ((WebAuthnPlus)getApplication()).getSignOnSuccessful();

    CheckBox demoMode = (CheckBox) findViewById(R.id.demo_mode);

    boolean demoModeValue = sharedPreferences.getBoolean(getString(R.string.demo_mode_key), true);
    demoMode.setChecked(demoModeValue);

    demoMode.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

        @Override
        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
          SharedPreferences.Editor prefEditor = sharedPreferences.edit();
          DataBaseManager dataBaseManager = new DataBaseManager(AboutTnx.this);

          try {
            if (isChecked) {
              prefEditor.putBoolean(getString(R.string.demo_mode_key), true);
              log("demo_mode_key::true");
            } else {
              prefEditor.putBoolean(getString(R.string.demo_mode_key), false);
              dataBaseManager.deleteTestCredentials();
              log("demo_mode_key::false::deleteTestCredentials()");
            }
            prefEditor.apply();

            boolean demoMode = sharedPreferences.getBoolean(getString(R.string.demo_mode_key), true);
            log("########AboutTnx::demoMode::" + demoMode);
          } finally {
            dataBaseManager.close();
          }
        }
      }
    );
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {

    if (signOnSuccessful) {
      getMenuInflater().inflate(R.menu.menu_about_tnx_signed_on, menu);
    } else {
      getMenuInflater().inflate(R.menu.menu_about_tnx, menu);
    }
    return true;
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {

    boolean result = super.onOptionsItemSelected(item);

    if (signOnSuccessful) {

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

    } else {

      switch (item.getItemId()) {

        case R.id.activate_password:

          Intent activatePassword = new Intent(this, ActivatePassword.class);
          startActivity(activatePassword);

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
    }

    return result;
  }
}







