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

import android.content.Context;
import android.database.Cursor;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.SimpleCursorAdapter;
import android.widget.TextView;

public class CursorAdapterContacts extends SimpleCursorAdapter {

  private Cursor cursor;
  private Context context;

  CursorAdapterContacts(Context context, int layout, Cursor cursor, String[] from, int[] to) {
    super(context, layout, cursor, from, to, 0);
    this.cursor = cursor;
    this.context = context;
  }

  // ------------------------------------------------------------------------------------------------------------------

  public View getView(int pos, View inView, ViewGroup parent) {

    View view = inView;

    if (view == null) {
      LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
      if (inflater != null) {
        view = inflater.inflate(R.layout.item_contact, parent, false);
      }
    }

    this.cursor.moveToPosition(pos);

    if (view != null) {

      String displayName = this.cursor.getString(this.cursor.getColumnIndex("displayName"));
      TextView displayNameView = (TextView) view.findViewById(R.id.display_name);
      displayNameView.setText(displayName);

      String phoneNumber = this.cursor.getString(this.cursor.getColumnIndex("phoneNumber"));
      TextView phoneNumberView = (TextView) view.findViewById(R.id.mobile_phone_number);
      phoneNumberView.setText(phoneNumber);

      String emailAddress = this.cursor.getString(this.cursor.getColumnIndex("emailAddress"));
      TextView emailAddressView = (TextView) view.findViewById(R.id.email_address);
      emailAddressView.setText(emailAddress);
    }

    return (view);
  }
}







