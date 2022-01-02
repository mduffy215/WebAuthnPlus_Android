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

import android.content.Context;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.SimpleCursorAdapter;
import android.widget.TextView;

import io.trustnexus.webauthnplus.util.Constants;

import io.trustnexus.webauthnplus.R;

import java.io.ByteArrayInputStream;

public class ImageCursorAdapterCredentials extends SimpleCursorAdapter {

  private Cursor cursor;
  private Context context;

  private final static boolean DEBUG = true;

  public ImageCursorAdapterCredentials(Context context, int layout, Cursor cursor, String[] from, int[] to) {
    super(context, layout, cursor, from, to, 0);
    this.cursor = cursor;
    this.context = context;
  }

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

  public View getView(int pos, View inView, ViewGroup parent) {

    View view = inView;

    if (view == null) {
      LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
      if (inflater != null) {
        view = inflater.inflate(R.layout.item_credential, parent, false);
      }
    }

    this.cursor.moveToPosition(pos);

    if (view != null){

      String providerName = this.cursor.getString(this.cursor.getColumnIndex(DataBaseManager.CREDENTIAL_PROVIDER_NAME));
      TextView providerNameView = (TextView) view.findViewById(R.id.provider_name);
      providerNameView.setText(providerName);

      String providerUrl = this.cursor.getString(this.cursor.getColumnIndex(DataBaseManager.DOMAIN_NAME));
      TextView providerUrlView = (TextView) view.findViewById(R.id.provider_url);
      providerUrlView.setText(providerUrl);

      String displayName = this.cursor.getString(this.cursor.getColumnIndex(DataBaseManager.DISPLAY_NAME));
      TextView displayNameView = (TextView) view.findViewById(R.id.display_name);
      displayNameView.setText(displayName);

      String credentialType = this.cursor.getString(this.cursor.getColumnIndex(DataBaseManager.CREDENTIAL_TYPE));

      ImageView imageView = (ImageView) view.findViewById(R.id.image_view_icon);

      switch (credentialType) {

        case "com.MMAIL.DISPLAY_ONLY":
          imageView.setImageResource(R.mipmap.m_mail);
          break;

        case "com.ivybank.DISPLAY_ONLY":
          imageView.setImageResource(R.mipmap.ivy_card);
          break;

        case "com.TXDL.DISPLAY_ONLY":
          imageView.setImageResource(R.mipmap.tdl);
          break;

        case "com.med_insurance.DISPLAY_ONLY":
          imageView.setImageResource(R.mipmap.med_insurance);
          break;

        case "com.social.DISPLAY_ONLY":
          imageView.setImageResource(R.mipmap.social);
          break;
        default:

          byte[] credentialIconByteArray = this.cursor.getBlob(this.cursor.getColumnIndex(DataBaseManager.CREDENTIAL_ICON));

          if (credentialIconByteArray != null && credentialIconByteArray.length > 1) {

            float scale = view.getResources().getDisplayMetrics().density;
            int iconWidth = (int)(scale*41);
            int iconHeight = (int)(scale*27);

            ByteArrayInputStream imageStream = new ByteArrayInputStream(credentialIconByteArray);
            Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
            Bitmap credentialIconBitMapScaled =   Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

            imageView.setImageBitmap(credentialIconBitMapScaled);

          } else {
            imageView.setImageResource(R.mipmap.app_icon);
          }
          break;
      }
    }

    return (view);
  }
}







