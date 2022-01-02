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

import android.Manifest;
import android.annotation.TargetApi;
import android.app.DialogFragment;
import android.app.ProgressDialog;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.provider.ContactsContract;
import androidx.annotation.NonNull;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import io.trustnexus.webauthnplus.R;

import io.trustnexus.webauthnplus.fundstransfer.SendFunds;
import io.trustnexus.webauthnplus.util.Constants;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Collections;

public class Contacts extends ListActivityBase  {

  private ProgressDialog progressDialog;
  private Handler updateBarHandler;
  private CursorAdapterContacts cursorAdapterContacts;
  private Cursor cursor;
  private int counter;
  final private int REQUEST_CODE_ASK_PERMISSIONS = 123;

  public static String[] FROM_CONTACTS = {"displayName", "phoneNumber", "emailAddress" };
  private static int[] TO_CONTACTS = {R.id.display_name, R.id.mobile_phone_number, R.id.email_address};

  // ------------------------------------------------------------------------------------------------------------------

  @TargetApi(Build.VERSION_CODES.M)
  @Override
  public void onCreate(Bundle savedInstanceState) {

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_contacts);
    progressDialog = new ProgressDialog(this);
    progressDialog.setMessage("Reading contacts...");
    progressDialog.setCancelable(false);
    progressDialog.show();
    updateBarHandler = new Handler();

    // ----------------------------------------------------------------------------------------------------------------

    ImageView imageView = findViewById(R.id.image_credential_icon);

    String contactsCredentialType = ((WebAuthnPlus)getApplication()).getSenderCredentialType();
    log("contactsCredentialType: " + contactsCredentialType);

    DataBaseManager dataBaseManager = new DataBaseManager(this);

    Cursor credentialCursor = dataBaseManager.retrieveCredentialByCredentialType(contactsCredentialType);

    boolean hasResults = credentialCursor.moveToFirst();
    log("hasResults: " + hasResults);

    byte[] credentialIconByteArray = credentialCursor.getBlob(credentialCursor.getColumnIndex(DataBaseManager.CREDENTIAL_ICON));

    if (credentialIconByteArray != null && credentialIconByteArray.length > 1) {

      float scale = getResources().getDisplayMetrics().density;
      int iconWidth = (int)(scale*41);
      int iconHeight = (int)(scale*27);

      ByteArrayInputStream imageStream = new ByteArrayInputStream(credentialIconByteArray);
      Bitmap credentialIconBitMap = BitmapFactory.decodeStream(imageStream);
      Bitmap credentialIconBitMapScaled =   Bitmap.createScaledBitmap(credentialIconBitMap, iconWidth, iconHeight, true);

      imageView.setImageBitmap(credentialIconBitMapScaled);
    }

    String providerName = credentialCursor.getString(credentialCursor.getColumnIndex(DataBaseManager.CREDENTIAL_PROVIDER_NAME));
    TextView providerNameView = findViewById(R.id.provider_name);
    providerNameView.setText(providerName);

    String providerUrl = credentialCursor.getString(credentialCursor.getColumnIndex(DataBaseManager.DOMAIN_NAME));
    TextView providerUrlView = findViewById(R.id.provider_url);
    providerUrlView.setText(providerUrl);

    String displayName = credentialCursor.getString(credentialCursor.getColumnIndex(DataBaseManager.DISPLAY_NAME));
    TextView displayNameView = findViewById(R.id.display_name);
    displayNameView.setText(displayName);

    displayContactsWrapper();
  }

  // ------------------------------------------------------------------------------------------------------------------

  protected void onListItemClick(ListView listView, View view, int position, long id) {

    if (!checkMaxIdleTimeExceeded()) {

      Cursor cursor = (Cursor) cursorAdapterContacts.getItem(position);

      String contactDisplayName = cursor.getString(cursor.getColumnIndex("displayName"));
      log("contactDisplayName: " + contactDisplayName);

      String contactPhoneNumber = cursor.getString(cursor.getColumnIndex("phoneNumber"));
      log("contactPhoneNumber: " + contactPhoneNumber);

      String emailAddress = cursor.getString(cursor.getColumnIndex("emailAddress"));
      log("emailAddress: " + emailAddress);

      if (contactPhoneNumber == null || emailAddress == null) {

        DialogFragment alertDialogFragmentMessage = AlertDialogFragmentMessage.newInstance(Constants.INSUFFICIENT_CONTACT_INFORMATION);
        alertDialogFragmentMessage.show(getFragmentManager(), "dialog");

      } else {

        ((WebAuthnPlus)getApplication()).setRecipientDsplayName(contactDisplayName);
        ((WebAuthnPlus)getApplication()).setRecipientPhoneNumber(contactPhoneNumber);
        ((WebAuthnPlus)getApplication()).setRecipientEmailAddress(emailAddress);

        Intent fundsTransfer = new Intent(this, SendFunds.class);
        startActivity(fundsTransfer);
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  private void displayContactsWrapper() {
    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {

      switch (checkSelfPermission(Manifest.permission.READ_CONTACTS)) {
        case PackageManager.PERMISSION_DENIED:
          requestPermissions(new String[]{android.Manifest.permission.READ_CONTACTS}, REQUEST_CODE_ASK_PERMISSIONS);
          break;

        case PackageManager.PERMISSION_GRANTED:
          displayContacts();
          break;

        default:
          requestPermissions(new String[]{android.Manifest.permission.READ_CONTACTS}, REQUEST_CODE_ASK_PERMISSIONS);
          break;
      }
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
    switch (requestCode) {
      case REQUEST_CODE_ASK_PERMISSIONS:
        if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
          displayContacts();
        } else {
          Toast.makeText(this, "READ_CONTACTS Denied", Toast.LENGTH_SHORT).show();
        }
        break;
      default:
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  public void displayContacts() {

    ArrayList<ContactItem> contactItemList = new ArrayList<>();

    ContentResolver contentResolver = getContentResolver();

    cursor = contentResolver.query(ContactsContract.Contacts.CONTENT_URI, null, null, null, null);

    if ( cursor != null && cursor.getCount() > 0) {
      counter = 1;
      while (cursor.moveToNext()) {

        ContactItem contactItem = new ContactItem();
        contactItemList.add(contactItem);

        // Update the progress message
        updateBarHandler.post(new Runnable() {
          public void run() {
            progressDialog.setMessage("Reading contacts : "+ counter++ +"/"+cursor.getCount());
          }
        });

        String contactId = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts._ID));
        log("contactId: " + contactId);
        contactItem.setContactId(contactId); 

        String displayName = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME));
        log("displayName: " + displayName);
        contactItem.setDisplayName(displayName);
        
        // ------------------------------------------------------------------------------------------------------------

        int hasPhoneNumber = Integer.parseInt(cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.HAS_PHONE_NUMBER)));

        if (hasPhoneNumber > 0) {
          //This is to read multiple phone numbers associated with the same contact
          Cursor phoneCursor = contentResolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null,
                                                     "(" + ContactsContract.CommonDataKinds.Phone.CONTACT_ID + " = ? )", new String[] { contactId }, null);
          
          if (phoneCursor != null && phoneCursor.getCount() > 0) {

            while (phoneCursor.moveToNext()) {

              int indexOfDisplayNumber = phoneCursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER);
              String phoneNumber = phoneCursor.getString(indexOfDisplayNumber);
              log("phoneNumber: " + phoneNumber);
              contactItem.setPhoneNumber(phoneNumber);

              int phoneType = phoneCursor.getInt(phoneCursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.TYPE));

              // Get the TYPE_MOBILE or simply get the last number listed.
              if (phoneType == ContactsContract.CommonDataKinds.Phone.TYPE_MOBILE) {
                break;
              }
            }

            phoneCursor.close();
          }
        }

        // ------------------------------------------------------------------------------------------------------------

        //This is to read multiple email addresses associated with the same contact
        Cursor emailCursor = contentResolver.query(ContactsContract.CommonDataKinds.Email.CONTENT_URI, null,
                                                   ContactsContract.CommonDataKinds.Email.CONTACT_ID + " = ?", new String[] { contactId }, null);

        if (emailCursor != null && emailCursor.getCount() > 0) {

          while (emailCursor.moveToNext()) {

            int indexOfEmailAddress = emailCursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.DATA);
            String emailAddress = emailCursor.getString(indexOfEmailAddress);
            log("emailAddress: " + emailAddress);
            contactItem.setEmailAddress(emailAddress);
            
            int emailType = emailCursor.getInt(emailCursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.TYPE));
            
            if (emailType == ContactsContract.CommonDataKinds.Email.TYPE_HOME) {
              break;
            }
          }
          emailCursor.close();
        }
      }

      // --------------------------------------------------------------------------------------------------------------

      Collections.sort(contactItemList);

      String[] columns = { "_id", "displayName", "phoneNumber", "emailAddress" };
      MatrixCursor matrixCursor= new MatrixCursor(columns);

      for (ContactItem contactItem2 : contactItemList) {
        matrixCursor.addRow(new Object[] { contactItem2.getContactId(), contactItem2.getDisplayName(), contactItem2.getPhoneNumber(), contactItem2.getEmailAddress() });
      }

      cursorAdapterContacts = new CursorAdapterContacts(this, R.layout.item_contact, matrixCursor, FROM_CONTACTS, TO_CONTACTS);
      setListAdapter(cursorAdapterContacts);

      // Dismiss the progressbar after 500 millisecondds
      updateBarHandler.postDelayed(new Runnable() {
        @Override
        public void run() {
          progressDialog.cancel();
        }
      }, 500);
    }
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {

    boolean result = super.onCreateOptionsMenu(menu);

    MenuInflater menuInflater = getMenuInflater();
    menuInflater.inflate(R.menu.menu_contacts, menu);

    return result;
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {

    boolean result = super.onOptionsItemSelected(item);

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

      case R.id.about_tnx:

        Intent aboutTnx = new Intent(this, AboutTnx.class);
        startActivity(aboutTnx);

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

    return result;
  }
}







