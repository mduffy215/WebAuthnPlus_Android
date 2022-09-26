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

package io.trustnexus.webauthnplusb;

import android.app.DialogFragment;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.telephony.PhoneNumberFormattingTextWatcher;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.InputMethodManager;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import com.google.firebase.messaging.FirebaseMessaging;

import io.trustnexus.webauthnplusb.util.Constants;
import io.trustnexus.webauthnplusb.util.CryptoUtilities;
import io.trustnexus.webauthnplusb.util.Utilities;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;

public class Profile extends ActivityBase implements OnClickListener, OnItemSelectedListener {

    private SharedPreferences sharedPreferences;
    private boolean userCreated;
    private String userSecurityKeyHex;
    private PrivateKey privateKey;

    private EditText screenName;
    private EditText email;
    private TextView messageOne;
    private TextView messageTwo;
    private TextView messageThree;
    private TextView messageFour;

    private EditText firstName;
    private EditText lastName;
    private EditText phone;

    private EditText legalAddressLineOne;
    private EditText legalAddressLineTwo;
    private EditText legalCity;
    private EditText legalState;
    private EditText legalPostalCode;
    private Spinner legalCountry;

    private CheckBox sameAddress;

    private EditText mailingAddressLineOne;
    private EditText mailingAddressLineTwo;
    private EditText mailingCity;
    private EditText mailingState;
    private EditText mailingPostalCode;
    private Spinner mailingCountry;

    private EditText organizationName;
    private EditText organizationUrl;
    private EditText organizationTitle;
    private EditText organizationPhone;

    private EditText organizationAddressLineOne;
    private EditText organizationAddressLineTwo;
    private EditText organizationCity;
    private EditText organizationState;
    private EditText organizationPostalCode;
    private Spinner organizationCountry;

    private String legalCountryValue;
    private String mailingCountryValue;
    private String organizationCountryValue;

    private ProgressDialog progressDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_profile);

        // ----------------------------------------------------------------------------------------------------------------

        this.screenName = findViewById(R.id.screen_name);
        this.email = findViewById(R.id.contact_email);

        this.messageOne = findViewById(R.id.message_one);
        this.messageOne.setVisibility(TextView.GONE);
        this.messageTwo = findViewById(R.id.message_two);
        this.messageTwo.setVisibility(TextView.GONE);

        this.messageThree = findViewById(R.id.message_three);
        this.messageThree.setVisibility(TextView.GONE);
        this.messageFour = findViewById(R.id.message_four);
        this.messageFour.setVisibility(TextView.GONE);

        this.firstName = findViewById(R.id.first_name);
        this.lastName = findViewById(R.id.last_name);
        this.phone = findViewById(R.id.phone);
        this.phone.addTextChangedListener(new PhoneNumberFormattingTextWatcher());

        this.legalAddressLineOne = findViewById(R.id.legal_address_line_one);
        this.legalAddressLineTwo = findViewById(R.id.legal_address_line_two);
        this.legalCity = findViewById(R.id.legal_city);
        this.legalState = findViewById(R.id.legal_state);
        this.legalPostalCode = findViewById(R.id.legal_postal_code);

        this.legalCountry = findViewById(R.id.legal_country);
        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(this, R.array.countries, R.layout.spinner_text);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        this.legalCountry.setAdapter(adapter);
        this.legalCountry.setOnItemSelectedListener(this);

        this.sameAddress = findViewById(R.id.same_address);

        this.mailingAddressLineOne = findViewById(R.id.mailing_address_line_one);
        this.mailingAddressLineTwo = findViewById(R.id.mailing_address_line_two);
        this.mailingCity = findViewById(R.id.mailing_city);
        this.mailingState = findViewById(R.id.mailing_state);
        this.mailingPostalCode = findViewById(R.id.mailing_postal_code);

        this.mailingCountry = findViewById(R.id.mailing_country);
        adapter = ArrayAdapter.createFromResource(this, R.array.countries, R.layout.spinner_text);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        this.mailingCountry.setAdapter(adapter);
        this.mailingCountry.setOnItemSelectedListener(this);

        this.organizationName = findViewById(R.id.organization_name);
        this.organizationUrl = findViewById(R.id.organization_url);
        this.organizationTitle = findViewById(R.id.organization_title);
        this.organizationPhone = findViewById(R.id.organization_phone);
        this.organizationPhone.addTextChangedListener(new PhoneNumberFormattingTextWatcher());

        this.organizationAddressLineOne = findViewById(R.id.organization_address_line_one);
        this.organizationAddressLineTwo = findViewById(R.id.organization_address_line_two);
        this.organizationCity = findViewById(R.id.organization_city);
        this.organizationState = findViewById(R.id.organization_state);
        this.organizationPostalCode = findViewById(R.id.organization_postal_code);

        this.organizationCountry = findViewById(R.id.organization_country);
        adapter = ArrayAdapter.createFromResource(this, R.array.countries, R.layout.spinner_text);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        this.organizationCountry.setAdapter(adapter);
        this.organizationCountry.setOnItemSelectedListener(this);

        findViewById(R.id.save_profile_one).setOnClickListener(this);
        findViewById(R.id.save_profile_two).setOnClickListener(this);

        // ----------------------------------------------------------------------------------------------------------------

        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);
        String userCreatedString = sharedPreferences.getString(getString(R.string.user_created_key), getString(R.string.empty_string));
        log("######## userCreatedString: " + userCreatedString);

        assert userCreatedString != null;
        if (userCreatedString.equals(getString(R.string.user_created))) {

            userCreated = true;

            userSecurityKeyHex = ((WebAuthnPlus) getApplication()).getUserSecurityKeyHex();
            log("######## userSecurityKeyHex: " + userSecurityKeyHex);

            String encryptedPrivateKeyHex = sharedPreferences.getString(this.getString(R.string.crypto_private_key), this.getString(R.string.empty_string));
            log("encryptedPrivateKeyHex: " + encryptedPrivateKeyHex);

            privateKey = CryptoUtilities.retrieveUserPrivateKey(userSecurityKeyHex, encryptedPrivateKeyHex);

            /*
             * Display all the current values in the EditText dialog boxes.
             */
            this.displayProfile();
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private void displayProfile() {

        String screenNameValueEncrypted = sharedPreferences.getString(getString(R.string.screen_name_key), getString(R.string.empty_string));
        String screenNameValue = CryptoUtilities.decrypt(userSecurityKeyHex, screenNameValueEncrypted);
        this.screenName.setText(screenNameValue);
        log("screenNameValue: " + screenNameValue);

        String emailValueEncrypted = sharedPreferences.getString(getString(R.string.email_key), getString(R.string.empty_string));
        String emailValue = CryptoUtilities.decrypt(userSecurityKeyHex, emailValueEncrypted);
        this.email.setText(emailValue);
        log("emailValue: " + emailValue);

        // ----------------------------------------------------------------------------------------------------------------

        String firstNameValueEncrypted = sharedPreferences.getString(getString(R.string.first_name_key), getString(R.string.empty_string));
        String firstNameValue = CryptoUtilities.decrypt(userSecurityKeyHex, firstNameValueEncrypted);
        this.firstName.setText(firstNameValue);
        log("firstNameValue: " + firstNameValue);

        String lastNameValueEncrypted = sharedPreferences.getString(getString(R.string.last_name_key), getString(R.string.empty_string));
        String lastNameValue = CryptoUtilities.decrypt(userSecurityKeyHex, lastNameValueEncrypted);
        this.lastName.setText(lastNameValue);
        log("lastNameValue: " + lastNameValue);

        String phoneValueEncrypted = sharedPreferences.getString(getString(R.string.phone_key), getString(R.string.empty_string));
        String phoneValue = CryptoUtilities.decrypt(userSecurityKeyHex, phoneValueEncrypted);
        this.phone.setText(phoneValue);
        log("phoneValue: " + phoneValue);

        // ----------------------------------------------------------------------------------------------------------------

        String legalAddressLineOneValueEncrypted = sharedPreferences.getString(getString(R.string.legal_address_line_one_key), getString(R.string.empty_string));
        String legalAddressLineOneValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalAddressLineOneValueEncrypted);
        this.legalAddressLineOne.setText(legalAddressLineOneValue);
        log("legalAddressLineOneValue: " + legalAddressLineOneValue);

        String legalAddressLineTwoValueEncrypted = sharedPreferences.getString(getString(R.string.legal_address_line_two_key), getString(R.string.empty_string));
        String legalAddressLineTwoValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalAddressLineTwoValueEncrypted);
        this.legalAddressLineTwo.setText(legalAddressLineTwoValue);
        log("legalAddressLineTwoValue: " + legalAddressLineTwoValue);

        String legalCityValueEncrypted = sharedPreferences.getString(getString(R.string.legal_address_city_key), getString(R.string.empty_string));
        String legalCityValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalCityValueEncrypted);
        this.legalCity.setText(legalCityValue);
        log("legalCityValue: " + legalCityValue);

        String legalStateValueEncrypted = sharedPreferences.getString(getString(R.string.legal_address_state_key), getString(R.string.empty_string));
        String legalStateValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalStateValueEncrypted);
        this.legalState.setText(legalStateValue);
        log("legalStateValue: " + legalStateValue);

        String legalPostalCodeValueEncrypted = sharedPreferences.getString(getString(R.string.legal_address_postal_code_key), getString(R.string.empty_string));
        String legalPostalCodeValue = CryptoUtilities.decrypt(userSecurityKeyHex, legalPostalCodeValueEncrypted);
        this.legalPostalCode.setText(legalPostalCodeValue);
        log("legalPostalCodeValue: " + legalPostalCodeValue);

        String legalCountryValuePrefEncrypted = sharedPreferences.getString(getString(R.string.legal_address_country_key), getString(R.string.empty_string));
        String legalCountryValuePref = CryptoUtilities.decrypt(userSecurityKeyHex, legalCountryValuePrefEncrypted);
        log("legalCountryValuePref: " + legalCountryValuePref);

        if (!legalCountryValuePref.equals("")) {
            this.legalCountry.setSelection(((ArrayAdapter<String>) legalCountry.getAdapter()).getPosition(legalCountryValuePref));
            legalCountryValue = legalCountryValuePref;
        }

        // ----------------------------------------------------------------------------------------------------------------

        boolean sameAddressValue = sharedPreferences.getBoolean(getString(R.string.same_address_key), false);
        this.sameAddress.setChecked(sameAddressValue);

        // ----------------------------------------------------------------------------------------------------------------

        String mailingAddressLineOneValueEncrypted = sharedPreferences.getString(getString(R.string.mailing_address_line_one_key), getString(R.string.empty_string));
        String mailingAddressLineOneValue = CryptoUtilities.decrypt(userSecurityKeyHex, mailingAddressLineOneValueEncrypted);
        this.mailingAddressLineOne.setText(mailingAddressLineOneValue);
        log("mailingAddressLineOneValue: " + mailingAddressLineOneValue);

        String mailingAddressLineTwoValueEncrypted = sharedPreferences.getString(getString(R.string.mailing_address_line_two_key), getString(R.string.empty_string));
        String mailingAddressLineTwoValue = CryptoUtilities.decrypt(userSecurityKeyHex, mailingAddressLineTwoValueEncrypted);
        this.mailingAddressLineTwo.setText(mailingAddressLineTwoValue);
        log("mailingAddressLineTwoValue: " + mailingAddressLineTwoValue);

        String mailingCityValueEncrypted = sharedPreferences.getString(getString(R.string.mailing_address_city_key), getString(R.string.empty_string));
        String mailingCityValue = CryptoUtilities.decrypt(userSecurityKeyHex, mailingCityValueEncrypted);
        this.mailingCity.setText(mailingCityValue);
        log("mailingCityValue: " + mailingCityValue);

        String mailingStateValueEncrypted = sharedPreferences.getString(getString(R.string.mailing_address_state_key), getString(R.string.empty_string));
        String mailingStateValue = CryptoUtilities.decrypt(userSecurityKeyHex, mailingStateValueEncrypted);
        this.mailingState.setText(mailingStateValue);
        log("mailingStateValue: " + mailingStateValue);

        String mailingPostalCodeValueEncrypted = sharedPreferences.getString(getString(R.string.mailing_address_postal_code_key), getString(R.string.empty_string));
        String mailingPostalCodeValue = CryptoUtilities.decrypt(userSecurityKeyHex, mailingPostalCodeValueEncrypted);
        this.mailingPostalCode.setText(mailingPostalCodeValue);
        log("mailingPostalCodeValue: " + mailingPostalCodeValue);

        String mailingCountryValuePrefEncrypted = sharedPreferences.getString(getString(R.string.mailing_address_country_key), getString(R.string.empty_string));
        String mailingCountryValuePref = CryptoUtilities.decrypt(userSecurityKeyHex, mailingCountryValuePrefEncrypted);
        log("mailingCountryValuePref: " + mailingCountryValuePref);

        if (!mailingCountryValuePref.equals("")) {
            this.mailingCountry.setSelection(((ArrayAdapter<String>) mailingCountry.getAdapter()).getPosition(mailingCountryValuePref));
            mailingCountryValue = mailingCountryValuePref;
        }

        // ----------------------------------------------------------------------------------------------------------------

        String organizationNameValueEncrypted = sharedPreferences.getString(getString(R.string.organization_name_key), getString(R.string.empty_string));
        String organizationNameValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationNameValueEncrypted);
        this.organizationName.setText(organizationNameValue);
        log("organizationNameValue: " + organizationNameValue);

        String organizationUrlValueEncrypted = sharedPreferences.getString(getString(R.string.organization_url_key), getString(R.string.empty_string));
        String organizationUrlValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationUrlValueEncrypted);
        this.organizationUrl.setText(organizationUrlValue);
        log("organizationUrlValue: " + organizationUrlValue);

        String organizationTitleValueEncrypted = sharedPreferences.getString(getString(R.string.organization_title_key), getString(R.string.empty_string));
        String organizationTitleValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationTitleValueEncrypted);
        this.organizationTitle.setText(organizationTitleValue);
        log("organizationTitleValue: " + organizationTitleValue);

        String organizationPhoneValueEncrypted = sharedPreferences.getString(getString(R.string.organization_phone_key), getString(R.string.empty_string));
        String organizationPhoneValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationPhoneValueEncrypted);
        this.organizationPhone.setText(organizationPhoneValue);
        log("organizationPhoneValue: " + organizationPhoneValue);

        // ----------------------------------------------------------------------------------------------------------------

        String organizationAddressLineOneValueEncrypted = sharedPreferences.getString(getString(R.string.organization_address_line_one_key), getString(R.string.empty_string));
        String organizationAddressLineOneValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationAddressLineOneValueEncrypted);
        this.organizationAddressLineOne.setText(organizationAddressLineOneValue);
        log("organizationAddressLineOneValue: " + organizationAddressLineOneValue);

        String organizationAddressLineTwoValueEncrypted = sharedPreferences.getString(getString(R.string.organization_address_line_two_key), getString(R.string.empty_string));
        String organizationAddressLineTwoValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationAddressLineTwoValueEncrypted);
        this.organizationAddressLineTwo.setText(organizationAddressLineTwoValue);
        log("organizationAddressLineTwoValue: " + organizationAddressLineTwoValue);

        String organizationCityValueEncrypted = sharedPreferences.getString(getString(R.string.organization_address_city_key), getString(R.string.empty_string));
        String organizationCityValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationCityValueEncrypted);
        this.organizationCity.setText(organizationCityValue);
        log("organizationCityValue: " + organizationCityValue);

        String organizationStateValueEncrypted = sharedPreferences.getString(getString(R.string.organization_address_state_key), getString(R.string.empty_string));
        String organizationStateValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationStateValueEncrypted);
        this.organizationState.setText(organizationStateValue);
        log("organizationStateValue: " + organizationStateValue);

        String organizationPostalCodeValueEncrypted = sharedPreferences.getString(getString(R.string.organization_address_postal_code_key), getString(R.string.empty_string));
        String organizationPostalCodeValue = CryptoUtilities.decrypt(userSecurityKeyHex, organizationPostalCodeValueEncrypted);
        this.organizationPostalCode.setText(organizationPostalCodeValue);
        log("organizationPostalCodeValue: " + organizationPostalCodeValue);

        String organizationCountryValuePrefEncrypted = sharedPreferences.getString(getString(R.string.organization_address_country_key), getString(R.string.empty_string));
        String organizationCountryValuePref = CryptoUtilities.decrypt(userSecurityKeyHex, organizationCountryValuePrefEncrypted);
        log("organizationCountryValuePref: " + organizationCountryValuePref);

        if (!organizationCountryValuePref.equals("")) {
            this.organizationCountry.setSelection(((ArrayAdapter<String>) organizationCountry.getAdapter()).getPosition(organizationCountryValuePref));
            organizationCountryValue = organizationCountryValuePref;
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    /*
     * Thx to Jon Skeet for this simple and elegant solution for referencing the outer class from within an inner class.
     * https://stackoverflow.com/questions/1816458/getting-hold-of-the-outer-class-object-from-the-inner-class-object
     */
    Profile getOuter() {
        return Profile.this;
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void onClick(View arg0) {

        InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);

        if (inputMethodManager != null) {
            inputMethodManager.hideSoftInputFromWindow(screenName.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(email.getWindowToken(), 0);

            inputMethodManager.hideSoftInputFromWindow(firstName.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(lastName.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(phone.getWindowToken(), 0);

            inputMethodManager.hideSoftInputFromWindow(legalAddressLineOne.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(legalAddressLineTwo.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(legalCity.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(legalState.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(legalPostalCode.getWindowToken(), 0);

            inputMethodManager.hideSoftInputFromWindow(mailingAddressLineOne.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(mailingAddressLineTwo.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(mailingCity.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(mailingState.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(mailingPostalCode.getWindowToken(), 0);

            inputMethodManager.hideSoftInputFromWindow(organizationName.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(organizationUrl.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(organizationTitle.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(organizationPhone.getWindowToken(), 0);

            inputMethodManager.hideSoftInputFromWindow(organizationAddressLineOne.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(organizationAddressLineTwo.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(organizationCity.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(organizationState.getWindowToken(), 0);
            inputMethodManager.hideSoftInputFromWindow(organizationPostalCode.getWindowToken(), 0);
        }

        this.messageOne.setVisibility(TextView.GONE);
        this.messageTwo.setVisibility(TextView.GONE);
        this.messageThree.setVisibility(TextView.GONE);
        this.messageFour.setVisibility(TextView.GONE);

        if (!checkMaxIdleTimeExceeded()) {

            log(this.screenName.getText().toString() + "  " + this.screenName.getText().toString().length());
            log(this.email.getText().toString());

            if (TextUtils.isEmpty(this.screenName.getText().toString()) || !Utilities.isEmailValid(this.email.getText().toString())) {

                DialogFragment alertDialogFragmentMessage = AlertDialogFragmentMessage.newInstance(Constants.INCOMPLETE_PROFILE);
                alertDialogFragmentMessage.show(getFragmentManager(), "dialog");

            } else {

                Editor prefEditor = sharedPreferences.edit();

                // ------------------------------------------------------------------------------------------------------------

                /*
                 * If the user has not yet been created he/she has no security credentials(i.e., no private/public key
                 * and no user security key); therefore, it is not yet possible to sign a transaction UUID or encrypt values.
                 */

                if (!userCreated) {

                    String userUuid = CryptoUtilities.generateUuid();
                    log("userUuid: " + userUuid);

                    /*
                     * Store the userUuid in the shared preferences for future reference.
                     *
                     * This value will be encrypted during the next step of the sign up process  ProcessCreateSecurityKey after
                     * the user's userSecurityKey is created.
                     */
                    prefEditor.putString(this.getString(R.string.user_uuid_key), userUuid);
                    prefEditor.apply();

                    // ----------------------------------------------------------------------------------------------------------

                    /*
                     * Similarly, when the user's userSecurityKey is created, we will store an encrypted version of the
                     * firebaseDeviceId in the SharedPreferences.  We could of course generate the firebaseDeviceId each time we
                     * need it; however, we will store it in order to make a comparison to see if the value has changed and
                     * needs to be updated on the server.
                     */
                    log("Getting firebaseDeviceId.");

                    FirebaseMessaging.getInstance().getToken()
                            .addOnCompleteListener(task -> {

                                if (!task.isSuccessful()) {
                                    log("Fetching FCM registration token failed" + task.getException());
                                    return;
                                }

                                // Get new FCM registration token
                                String firebaseDeviceId = task.getResult();
                                log("firebaseDeviceId: " + firebaseDeviceId);

                                /*
                                 * The following values will be encrypted during the next step of the sign up process ProcessCreateSecurityKey after
                                 * the user's userSecurityKey is created.
                                 */

                                prefEditor.putString(getOuter().getString(R.string.firebase_device_id), firebaseDeviceId);
                                prefEditor.putString(getString(R.string.screen_name_key), getOuter().screenName.getText().toString());
                                prefEditor.putString(getString(R.string.email_key), getOuter().email.getText().toString());

                                prefEditor.putString(getString(R.string.first_name_key), getOuter().firstName.getText().toString());
                                prefEditor.putString(getString(R.string.last_name_key), getOuter().lastName.getText().toString());
                                prefEditor.putString(getString(R.string.phone_key), getOuter().phone.getText().toString());

                                prefEditor.putString(getString(R.string.legal_address_line_one_key), getOuter().legalAddressLineOne.getText().toString());
                                prefEditor.putString(getString(R.string.legal_address_line_two_key), getOuter().legalAddressLineTwo.getText().toString());
                                prefEditor.putString(getString(R.string.legal_address_city_key), getOuter().legalCity.getText().toString());
                                prefEditor.putString(getString(R.string.legal_address_state_key), getOuter().legalState.getText().toString());
                                prefEditor.putString(getString(R.string.legal_address_postal_code_key), getOuter().legalPostalCode.getText().toString());
                                prefEditor.putString(getString(R.string.legal_address_country_key), getOuter().legalCountryValue);

                                prefEditor.putBoolean(getString(R.string.same_address_key), getOuter().sameAddress.isChecked());

                                prefEditor.putString(getString(R.string.mailing_address_line_one_key), getOuter().mailingAddressLineOne.getText().toString());
                                prefEditor.putString(getString(R.string.mailing_address_line_two_key), getOuter().mailingAddressLineTwo.getText().toString());
                                prefEditor.putString(getString(R.string.mailing_address_city_key), getOuter().mailingCity.getText().toString());
                                prefEditor.putString(getString(R.string.mailing_address_state_key), getOuter().mailingState.getText().toString());
                                prefEditor.putString(getString(R.string.mailing_address_postal_code_key), getOuter().mailingPostalCode.getText().toString());
                                prefEditor.putString(getString(R.string.mailing_address_country_key), getOuter().mailingCountryValue);

                                prefEditor.putString(getString(R.string.organization_name_key), getOuter().organizationName.getText().toString());
                                prefEditor.putString(getString(R.string.organization_url_key), getOuter().organizationUrl.getText().toString());
                                prefEditor.putString(getString(R.string.organization_title_key), getOuter().organizationTitle.getText().toString());
                                prefEditor.putString(getString(R.string.organization_phone_key), getOuter().organizationPhone.getText().toString());

                                prefEditor.putString(getString(R.string.organization_address_line_one_key), getOuter().organizationAddressLineOne.getText().toString());
                                prefEditor.putString(getString(R.string.organization_address_line_two_key), getOuter().organizationAddressLineTwo.getText().toString());
                                prefEditor.putString(getString(R.string.organization_address_city_key), getOuter().organizationCity.getText().toString());
                                prefEditor.putString(getString(R.string.organization_address_state_key), getOuter().organizationState.getText().toString());
                                prefEditor.putString(getString(R.string.organization_address_postal_code_key), getOuter().organizationPostalCode.getText().toString());
                                prefEditor.putString(getString(R.string.organization_address_country_key), getOuter().organizationCountryValue);

                                prefEditor.apply();

                                // ----------------------------------------------------------------------------------------------------------

                                String[] paramStrings = CryptoUtilities.generateParams_CreateUser(sharedPreferences, Profile.this);

                                assert paramStrings != null;
                                String urlParameters = paramStrings[0];
                                String transferKeyHex = paramStrings[1];

                                String[] urlStrings = {Constants.CREATE_USER_URL, urlParameters, transferKeyHex};

                                ProcessCreateUser processCreateUser = new ProcessCreateUser(getOuter());
                                processCreateUser.execute(urlStrings);


                            });

                    // ----------------------------------------------------------------------------------------------------------


                } else {

                    /*
                     * If the user has been created he/she has security credentials(i.e., a private/public key and a user
                     * security key); therefore, it is possible to sign a transaction UUID and encrypt values.
                     *
                     * Save the encrypted values of the user profile in shared preferences.
                     */

                    String userUuidEncrypted = sharedPreferences.getString(getString(R.string.user_uuid_key), getString(R.string.empty_string));
                    String userUuid = CryptoUtilities.decrypt(userSecurityKeyHex, userUuidEncrypted);
                    log("userUuid: " + userUuid);

                    String screenNameForm = this.screenName.getText().toString();
                    if (screenNameForm.length() > 0) {
                        String screenNameEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, screenNameForm);
                        prefEditor.putString(getString(R.string.screen_name_key), screenNameEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.screen_name_key), "");
                    }

                    String emailForm = this.email.getText().toString();
                    if (emailForm.length() > 0) {
                        String emailEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, emailForm);
                        prefEditor.putString(getString(R.string.email_key), emailEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.email_key), "");
                    }

                    String firstNameForm = this.firstName.getText().toString();
                    if (firstNameForm.length() > 0) {
                        String firstNameEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, firstNameForm);
                        prefEditor.putString(getString(R.string.first_name_key), firstNameEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.first_name_key), "");
                    }

                    String lastNameForm = this.lastName.getText().toString();
                    if (lastNameForm.length() > 0) {
                        String lastNameEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, lastNameForm);
                        prefEditor.putString(getString(R.string.last_name_key), lastNameEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.last_name_key), "");
                    }

                    String phoneForm = this.phone.getText().toString();
                    if (phoneForm.length() > 0) {
                        String phoneEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, phoneForm);
                        prefEditor.putString(getString(R.string.phone_key), phoneEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.phone_key), "");
                    }

                    // ----------------------------------------------------------------------------------------------------------

                    String legalAddressLineOneForm = this.legalAddressLineOne.getText().toString();
                    if (legalAddressLineOneForm.length() > 0) {
                        String legalAddressLineOneEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, legalAddressLineOneForm);
                        prefEditor.putString(getString(R.string.legal_address_line_one_key), legalAddressLineOneEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.legal_address_line_one_key), "");
                    }

                    String legalAddressLineTwoForm = this.legalAddressLineTwo.getText().toString();
                    if (legalAddressLineTwoForm.length() > 0) {
                        String legalAddressLineTwoEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, legalAddressLineTwoForm);
                        prefEditor.putString(getString(R.string.legal_address_line_two_key), legalAddressLineTwoEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.legal_address_line_two_key), "");
                    }

                    String legalCityForm = this.legalCity.getText().toString();
                    if (legalCityForm.length() > 0) {
                        String legalCityEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, legalCityForm);
                        prefEditor.putString(getString(R.string.legal_address_city_key), legalCityEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.legal_address_city_key), "");
                    }

                    String legalStateForm = this.legalState.getText().toString();
                    if (legalStateForm.length() > 0) {
                        String legalStateEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, legalStateForm);
                        prefEditor.putString(getString(R.string.legal_address_state_key), legalStateEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.legal_address_state_key), "");
                    }

                    String legalPostalCodeForm = this.legalPostalCode.getText().toString();
                    if (legalPostalCodeForm.length() > 0) {
                        String legalPostalCodeEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, legalPostalCodeForm);
                        prefEditor.putString(getString(R.string.legal_address_postal_code_key), legalPostalCodeEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.legal_address_postal_code_key), "");
                    }

                    if (legalCountryValue != null && legalCountryValue.length() > 0) {
                        String legalCountryEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, legalCountryValue);
                        prefEditor.putString(getString(R.string.legal_address_country_key), legalCountryEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.legal_address_country_key), "");
                    }

                    // ----------------------------------------------------------------------------------------------------------

                    prefEditor.putBoolean(getString(R.string.same_address_key), this.sameAddress.isChecked());

                    // ----------------------------------------------------------------------------------------------------------

                    String mailingAddressLineOneForm = this.mailingAddressLineOne.getText().toString();
                    if (mailingAddressLineOneForm.length() > 0) {
                        String mailingAddressLineOneEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, mailingAddressLineOneForm);
                        prefEditor.putString(getString(R.string.mailing_address_line_one_key), mailingAddressLineOneEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.mailing_address_line_one_key), "");
                    }

                    String mailingAddressLineTwoForm = this.mailingAddressLineTwo.getText().toString();
                    if (mailingAddressLineTwoForm.length() > 0) {
                        String mailingAddressLineTwoEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, mailingAddressLineTwoForm);
                        prefEditor.putString(getString(R.string.mailing_address_line_two_key), mailingAddressLineTwoEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.mailing_address_line_two_key), "");
                    }

                    String mailingCityForm = this.mailingCity.getText().toString();
                    if (mailingCityForm.length() > 0) {
                        String mailingCityEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, mailingCityForm);
                        prefEditor.putString(getString(R.string.mailing_address_city_key), mailingCityEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.mailing_address_city_key), "");
                    }

                    String mailingStateForm = this.mailingState.getText().toString();
                    if (mailingStateForm.length() > 0) {
                        String mailingStateEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, mailingStateForm);
                        prefEditor.putString(getString(R.string.mailing_address_state_key), mailingStateEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.mailing_address_state_key), "");
                    }

                    String mailingPostalCodeForm = this.mailingPostalCode.getText().toString();
                    if (mailingPostalCodeForm.length() > 0) {
                        String mailingPostalCodeEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, mailingPostalCodeForm);
                        prefEditor.putString(getString(R.string.mailing_address_postal_code_key), mailingPostalCodeEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.mailing_address_postal_code_key), "");
                    }

                    if (mailingCountryValue != null && mailingCountryValue.length() > 0) {
                        String mailingCountryEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, mailingCountryValue);
                        prefEditor.putString(getString(R.string.mailing_address_country_key), mailingCountryEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.mailing_address_country_key), "");
                    }

                    // ----------------------------------------------------------------------------------------------------------

                    String organizationNameForm = this.organizationName.getText().toString();
                    if (organizationNameForm.length() > 0) {
                        String organizationNameEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationNameForm);
                        prefEditor.putString(getString(R.string.organization_name_key), organizationNameEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_name_key), "");
                    }

                    String organizationUrlForm = this.organizationUrl.getText().toString();
                    if (organizationUrlForm.length() > 0) {
                        String organizationUrlEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationUrlForm);
                        prefEditor.putString(getString(R.string.organization_url_key), organizationUrlEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_url_key), "");
                    }

                    String organizationTitleForm = this.organizationTitle.getText().toString();
                    if (organizationTitleForm.length() > 0) {
                        String organizationTitleEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationTitleForm);
                        prefEditor.putString(getString(R.string.organization_title_key), organizationTitleEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_title_key), "");
                    }

                    String organizationPhoneForm = this.organizationPhone.getText().toString();
                    if (organizationPhoneForm.length() > 0) {
                        String organizationPhoneEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationPhoneForm);
                        prefEditor.putString(getString(R.string.organization_phone_key), organizationPhoneEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_phone_key), "");
                    }

                    // ----------------------------------------------------------------------------------------------------------

                    String organizationAddressLineOneForm = this.organizationAddressLineOne.getText().toString();
                    if (organizationAddressLineOneForm.length() > 0) {
                        String organizationAddressLineOneEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationAddressLineOneForm);
                        prefEditor.putString(getString(R.string.organization_address_line_one_key), organizationAddressLineOneEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_address_line_one_key), "");
                    }

                    String organizationAddressLineTwoForm = this.organizationAddressLineTwo.getText().toString();
                    if (organizationAddressLineTwoForm.length() > 0) {
                        String organizationAddressLineTwoEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationAddressLineTwoForm);
                        prefEditor.putString(getString(R.string.organization_address_line_two_key), organizationAddressLineTwoEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_address_line_two_key), "");
                    }

                    String organizationCityForm = this.organizationCity.getText().toString();
                    if (organizationCityForm.length() > 0) {
                        String organizationCityEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationCityForm);
                        prefEditor.putString(getString(R.string.organization_address_city_key), organizationCityEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_address_city_key), "");
                    }

                    String organizationStateForm = this.organizationState.getText().toString();
                    if (organizationStateForm.length() > 0) {
                        String organizationStateEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationStateForm);
                        prefEditor.putString(getString(R.string.organization_address_state_key), organizationStateEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_address_state_key), "");
                    }

                    String organizationPostalCodeForm = this.organizationPostalCode.getText().toString();
                    if (organizationPostalCodeForm.length() > 0) {
                        String organizationPostalCodeEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationPostalCodeForm);
                        prefEditor.putString(getString(R.string.organization_address_postal_code_key), organizationPostalCodeEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_address_postal_code_key), "");
                    }

                    if (organizationCountryValue != null && organizationCountryValue.length() > 0) {
                        String organizationCountryEncrypted = CryptoUtilities.encrypt(userSecurityKeyHex, organizationCountryValue);
                        prefEditor.putString(getString(R.string.organization_address_country_key), organizationCountryEncrypted);
                    } else {
                        prefEditor.putString(getString(R.string.organization_address_country_key), "");
                    }

                    // ----------------------------------------------------------------------------------------------------------

                    prefEditor.apply();

                    // ----------------------------------------------------------------------------------------------------------

                    /*
                     * Update the user's profile.
                     */
                    String[] paramStrings = CryptoUtilities.generateParams_RetrieveTransactionUuid(userUuid, privateKey,
                            Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY_UUID,
                            Constants.MOBILE_APP_PROVIDER_PUBLIC_KEY);

                    assert paramStrings != null;
                    String urlParameters = paramStrings[0];
                    String transferKeyHex = paramStrings[1];

                    String[] urlStrings = {Constants.RETRIEVE_MOBILE_APP_PROVIDER_TRANSACTION_UUID_URL, urlParameters, transferKeyHex};

                    /*
                     * Retrieve a transaction UUID that is signed with the user's private key to verify the transaction.
                     * In the onPostExecute(...) method of ProcessRetrieveTransactionUuid control is transferred to
                     * ProcessUpdateUser.
                     */
                    ProcessRetrieveTransactionUuid processRetrieveTransactionUuid = new ProcessRetrieveTransactionUuid(this);
                    processRetrieveTransactionUuid.execute(urlStrings);
                }
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {

        this.messageOne.setVisibility(TextView.GONE);
        this.messageTwo.setVisibility(TextView.GONE);

        this.messageThree.setVisibility(TextView.GONE);
        this.messageFour.setVisibility(TextView.GONE);

        boolean result = super.onCreateOptionsMenu(menu);

        getMenuInflater().inflate(R.menu.menu_profile, menu);

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

            case R.id.about_tnx:

                Intent aboutTnx = new Intent(this, AboutTnx.class);
                startActivity(aboutTnx);

                break;

            case R.id.exit:

                ((WebAuthnPlus) getApplication()).setExitValues();

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

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {

        switch (adapterView.getId()) {

            case R.id.legal_country:
                legalCountryValue = adapterView.getItemAtPosition(position).toString();
                break;

            case R.id.mailing_country:
                mailingCountryValue = adapterView.getItemAtPosition(position).toString();
                break;

            case R.id.organization_country:
                organizationCountryValue = adapterView.getItemAtPosition(position).toString();
                break;

            default:
                break;
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void onNothingSelected(AdapterView<?> arg0) {
        // This method will never matter because there are validations on the
        // spinners.
    }

    // ------------------------------------------------------------------------------------------------------------------

    public boolean isNetworkAvailable() {

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = null;
        if (connectivityManager != null) {
            networkInfo = connectivityManager.getActiveNetworkInfo();
        }

        return networkInfo != null && networkInfo.isConnected();
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessCreateUser extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<Profile> activityReference;

        // only retain a weak reference to the activity
        ProcessCreateUser(Profile context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            Profile profile = activityReference.get();

            if (!profile.isNetworkAvailable()) {
                return profile.getString(R.string.network_unavailable);
            } else {

                String targetURL = urlStrings[0];
                log("targetURL::" + targetURL + "::");

                String urlParameters = urlStrings[1];
                log("urlParameters::" + urlParameters + "::");

                String transferKeyHex = urlStrings[2];

                URL url;
                HttpURLConnection connection = null;

                try {
                    url = new URL(targetURL);

                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();


                    log("inputStream::" + inputStream.toString() + "::");


                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, profile);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            Profile profile = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            profile.progressDialog = new ProgressDialog(profile);
            profile.progressDialog.setCancelable(false);
            profile.progressDialog.setTitle(profile.getString(R.string.app_name));
            profile.progressDialog.setMessage(profile.getString(R.string.initializing));
            profile.progressDialog.setIndeterminate(false);
            profile.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            profile.progressDialog.setProgress(0);
            profile.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            Profile profile = activityReference.get();

            log("RESULT::" + result + "::");

            profile.progressDialog.dismiss();

            if (result == null) {
                result = profile.getString(R.string.problem_with_authentication_server);
            }

            profile.messageOne.setVisibility(TextView.VISIBLE);
            profile.messageOne.setText(result);

            profile.messageThree.setVisibility(TextView.VISIBLE);
            profile.messageThree.setText(result);

            if (result.equals(Constants.USER_SUCCESSFULLY_CREATED)) {

                profile.messageTwo.setVisibility(TextView.VISIBLE);
                profile.messageTwo.setText(profile.getString(R.string.please_wait));

                profile.messageFour.setVisibility(TextView.VISIBLE);
                profile.messageFour.setText(profile.getString(R.string.please_wait));

                String passwordValue = ((WebAuthnPlus) profile.getApplication()).getPasswordValue();

                String[] paramStrings = CryptoUtilities.generateParams_CreateSecurityKey(passwordValue, profile.sharedPreferences, profile);

                assert paramStrings != null;
                String urlParameters = paramStrings[0];
                log("urlParameters: " + urlParameters);
                String transferKeyHex = paramStrings[1];
                log("transferKeyHex: " + transferKeyHex);
                profile.userSecurityKeyHex = paramStrings[2];
                log("profile.userSecurityKeyHex: " + profile.userSecurityKeyHex);

                ((WebAuthnPlus) profile.getApplication()).setUserSecurityKeyHex(profile.userSecurityKeyHex);

                String[] urlStrings = {Constants.CREATE_SECURITY_KEY_URL, urlParameters, transferKeyHex};

                ProcessCreateSecurityKey processCreateSecurityKey = new ProcessCreateSecurityKey(profile);
                processCreateSecurityKey.execute(urlStrings);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessCreateSecurityKey extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<Profile> activityReference;

        // only retain a weak reference to the activity
        ProcessCreateSecurityKey(Profile context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            Profile profile = activityReference.get();

            if (!profile.isNetworkAvailable()) {
                return profile.getString(R.string.network_unavailable);
            } else {

                String targetURL = urlStrings[0];
                String urlParameters = urlStrings[1];
                String transferKeyHex = urlStrings[2];

                URL url;
                HttpURLConnection connection = null;

                try {
                    url = new URL(targetURL);

                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, profile);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            Profile profile = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            profile.progressDialog = new ProgressDialog(profile);
            profile.progressDialog.setCancelable(false);
            profile.progressDialog.setTitle(profile.getString(R.string.app_name));
            profile.progressDialog.setMessage(profile.getString(R.string.initializing));
            profile.progressDialog.setIndeterminate(false);
            profile.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            profile.progressDialog.setProgress(0);
            profile.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            Profile profile = activityReference.get();

            log("RESULT::" + result + "::");

            profile.progressDialog.dismiss();

            if (result == null) {
                result = profile.getString(R.string.problem_with_authentication_server);
            }

            profile.messageOne.setVisibility(TextView.VISIBLE);
            profile.messageOne.setText(result);

            profile.messageThree.setVisibility(TextView.VISIBLE);
            profile.messageThree.setText(result);

            if (result.equals(Constants.SECURITY_KEY_CREATED)) {

                /*
                 * Now that the userSecurityKeyHex has been created, encrypt the user's SharedPreferences values.
                 */
                Editor prefEditor = profile.sharedPreferences.edit();

                // ------------------------------------------------------------------------------------------------------------

                String userUuid = profile.sharedPreferences.getString(profile.getString(R.string.user_uuid_key), profile.getString(R.string.empty_string));
                String userUuidEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, userUuid);
                prefEditor.putString(profile.getString(R.string.user_uuid_key), userUuidEncrypted);

                String firebaseDeviceId = profile.sharedPreferences.getString(profile.getString(R.string.firebase_device_id), profile.getString(R.string.empty_string));
                String firebaseDeviceIdEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, firebaseDeviceId);
                prefEditor.putString(profile.getString(R.string.firebase_device_id), firebaseDeviceIdEncrypted);

                // ------------------------------------------------------------------------------------------------------------

                String screenNameValue = profile.sharedPreferences.getString(profile.getString(R.string.screen_name_key), profile.getString(R.string.empty_string));
                String screenNameValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, screenNameValue);
                prefEditor.putString(profile.getString(R.string.screen_name_key), screenNameValueEncrypted);

                String emailValue = profile.sharedPreferences.getString(profile.getString(R.string.email_key), profile.getString(R.string.empty_string));
                String emailValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, emailValue);
                prefEditor.putString(profile.getString(R.string.email_key), emailValueEncrypted);

                // ----------------------------------------------------------------------------------------------------------------

                String firstNameValue = profile.sharedPreferences.getString(profile.getString(R.string.first_name_key), profile.getString(R.string.empty_string));
                String firstNameValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, firstNameValue);
                prefEditor.putString(profile.getString(R.string.first_name_key), firstNameValueEncrypted);

                String lastNameValue = profile.sharedPreferences.getString(profile.getString(R.string.last_name_key), profile.getString(R.string.empty_string));
                String lastNameValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, lastNameValue);
                prefEditor.putString(profile.getString(R.string.last_name_key), lastNameValueEncrypted);

                String phoneValue = profile.sharedPreferences.getString(profile.getString(R.string.phone_key), profile.getString(R.string.empty_string));
                String phoneValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, phoneValue);
                prefEditor.putString(profile.getString(R.string.phone_key), phoneValueEncrypted);

                // ----------------------------------------------------------------------------------------------------------------

                String legalAddressLineOneValue = profile.sharedPreferences.getString(profile.getString(R.string.legal_address_line_one_key), profile.getString(R.string.empty_string));
                String legalAddressLineOneValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, legalAddressLineOneValue);
                prefEditor.putString(profile.getString(R.string.legal_address_line_one_key), legalAddressLineOneValueEncrypted);

                String legalAddressLineTwoValue = profile.sharedPreferences.getString(profile.getString(R.string.legal_address_line_two_key), profile.getString(R.string.empty_string));
                String legalAddressLineTwoValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, legalAddressLineTwoValue);
                prefEditor.putString(profile.getString(R.string.legal_address_line_two_key), legalAddressLineTwoValueEncrypted);

                String legalCityValue = profile.sharedPreferences.getString(profile.getString(R.string.legal_address_city_key), profile.getString(R.string.empty_string));
                String legalCityValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, legalCityValue);
                prefEditor.putString(profile.getString(R.string.legal_address_city_key), legalCityValueEncrypted);

                String legalStateValue = profile.sharedPreferences.getString(profile.getString(R.string.legal_address_state_key), profile.getString(R.string.empty_string));
                String legalStateValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, legalStateValue);
                prefEditor.putString(profile.getString(R.string.legal_address_state_key), legalStateValueEncrypted);

                String legalPostalCodeValue = profile.sharedPreferences.getString(profile.getString(R.string.legal_address_postal_code_key), profile.getString(R.string.empty_string));
                String legalPostalCodeValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, legalPostalCodeValue);
                prefEditor.putString(profile.getString(R.string.legal_address_postal_code_key), legalPostalCodeValueEncrypted);

                String legalCountryValuePref = profile.sharedPreferences.getString(profile.getString(R.string.legal_address_country_key), profile.getString(R.string.empty_string));
                String legalCountryValuePrefEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, legalCountryValuePref);
                prefEditor.putString(profile.getString(R.string.legal_address_country_key), legalCountryValuePrefEncrypted);

                // ----------------------------------------------------------------------------------------------------------------

                String mailingAddressLineOneValue = profile.sharedPreferences.getString(profile.getString(R.string.mailing_address_line_one_key), profile.getString(R.string.empty_string));
                String mailingAddressLineOneValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, mailingAddressLineOneValue);
                prefEditor.putString(profile.getString(R.string.mailing_address_line_one_key), mailingAddressLineOneValueEncrypted);

                String mailingAddressLineTwoValue = profile.sharedPreferences.getString(profile.getString(R.string.mailing_address_line_two_key), profile.getString(R.string.empty_string));
                String mailingAddressLineTwoValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, mailingAddressLineTwoValue);
                prefEditor.putString(profile.getString(R.string.mailing_address_line_two_key), mailingAddressLineTwoValueEncrypted);

                String mailingCityValue = profile.sharedPreferences.getString(profile.getString(R.string.mailing_address_city_key), profile.getString(R.string.empty_string));
                String mailingCityValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, mailingCityValue);
                prefEditor.putString(profile.getString(R.string.mailing_address_city_key), mailingCityValueEncrypted);

                String mailingStateValue = profile.sharedPreferences.getString(profile.getString(R.string.mailing_address_state_key), profile.getString(R.string.empty_string));
                String mailingStateValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, mailingStateValue);
                prefEditor.putString(profile.getString(R.string.mailing_address_state_key), mailingStateValueEncrypted);

                String mailingPostalCodeValue = profile.sharedPreferences.getString(profile.getString(R.string.mailing_address_postal_code_key), profile.getString(R.string.empty_string));
                String mailingPostalCodeValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, mailingPostalCodeValue);
                prefEditor.putString(profile.getString(R.string.mailing_address_postal_code_key), mailingPostalCodeValueEncrypted);

                String mailingCountryValuePref = profile.sharedPreferences.getString(profile.getString(R.string.mailing_address_country_key), profile.getString(R.string.empty_string));
                String mailingCountryValuePrefEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, mailingCountryValuePref);
                prefEditor.putString(profile.getString(R.string.mailing_address_country_key), mailingCountryValuePrefEncrypted);

                // ----------------------------------------------------------------------------------------------------------------

                String organizationNameValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_name_key), profile.getString(R.string.empty_string));
                String organizationNameValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationNameValue);
                prefEditor.putString(profile.getString(R.string.organization_name_key), organizationNameValueEncrypted);

                String organizationUrlValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_url_key), profile.getString(R.string.empty_string));
                String organizationUrlValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationUrlValue);
                prefEditor.putString(profile.getString(R.string.organization_url_key), organizationUrlValueEncrypted);

                String organizationTitleValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_title_key), profile.getString(R.string.empty_string));
                String organizationTitleValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationTitleValue);
                prefEditor.putString(profile.getString(R.string.organization_title_key), organizationTitleValueEncrypted);

                String organizationPhoneValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_phone_key), profile.getString(R.string.empty_string));
                String organizationPhoneValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationPhoneValue);
                prefEditor.putString(profile.getString(R.string.organization_phone_key), organizationPhoneValueEncrypted);

                // ----------------------------------------------------------------------------------------------------------------

                String organizationAddressLineOneValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_address_line_one_key), profile.getString(R.string.empty_string));
                String organizationAddressLineOneValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationAddressLineOneValue);
                prefEditor.putString(profile.getString(R.string.organization_address_line_one_key), organizationAddressLineOneValueEncrypted);

                String organizationAddressLineTwoValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_address_line_two_key), profile.getString(R.string.empty_string));
                String organizationAddressLineTwoValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationAddressLineTwoValue);
                prefEditor.putString(profile.getString(R.string.organization_address_line_two_key), organizationAddressLineTwoValueEncrypted);

                String organizationCityValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_address_city_key), profile.getString(R.string.empty_string));
                String organizationCityValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationCityValue);
                prefEditor.putString(profile.getString(R.string.organization_address_city_key), organizationCityValueEncrypted);

                String organizationStateValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_address_state_key), profile.getString(R.string.empty_string));
                String organizationStateValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationStateValue);
                prefEditor.putString(profile.getString(R.string.organization_address_state_key), organizationStateValueEncrypted);

                String organizationPostalCodeValue = profile.sharedPreferences.getString(profile.getString(R.string.organization_address_postal_code_key), profile.getString(R.string.empty_string));
                String organizationPostalCodeValueEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationPostalCodeValue);
                prefEditor.putString(profile.getString(R.string.organization_address_postal_code_key), organizationPostalCodeValueEncrypted);

                String organizationCountryValuePref = profile.sharedPreferences.getString(profile.getString(R.string.organization_address_country_key), profile.getString(R.string.empty_string));
                String organizationCountryValuePrefEncrypted = CryptoUtilities.encrypt(profile.userSecurityKeyHex, organizationCountryValuePref);
                prefEditor.putString(profile.getString(R.string.organization_address_country_key), organizationCountryValuePrefEncrypted);

                // ----------------------------------------------------------------------------------------------------------------

                prefEditor.apply();

                // ----------------------------------------------------------------------------------------------------------------

                String[] paramStrings = CryptoUtilities.generateParams_CreateUserPublicKey(profile.userSecurityKeyHex, profile.sharedPreferences, profile);

                assert paramStrings != null;
                String urlParameters = paramStrings[0];
                String transferKeyHex = paramStrings[1];

                String[] urlStrings = {Constants.CREATE_USER_PUBLIC_KEY_URL, urlParameters, transferKeyHex};

                ProcessCreateUserPublicKey processCreateUserPublicKey = new ProcessCreateUserPublicKey(profile);
                processCreateUserPublicKey.execute(urlStrings);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessCreateUserPublicKey extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<Profile> activityReference;

        // only retain a weak reference to the activity
        ProcessCreateUserPublicKey(Profile context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            Profile profile = activityReference.get();

            if (!profile.isNetworkAvailable()) {
                return profile.getString(R.string.network_unavailable);
            } else {

                String targetURL = urlStrings[0];
                String urlParameters = urlStrings[1];
                String transferKeyHex = urlStrings[2];

                URL url;
                HttpURLConnection connection = null;

                try {
                    url = new URL(targetURL);

                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, profile);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            Profile profile = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            profile.progressDialog = new ProgressDialog(profile);
            profile.progressDialog.setCancelable(false);
            profile.progressDialog.setTitle(profile.getString(R.string.app_name));
            profile.progressDialog.setMessage(profile.getString(R.string.creating_public_key));
            profile.progressDialog.setIndeterminate(false);
            profile.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            profile.progressDialog.setProgress(0);
            profile.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            Profile profile = activityReference.get();

            log("RESULT::" + result + "::");

            profile.progressDialog.dismiss();

            if (result == null) {
                result = profile.getString(R.string.problem_with_authentication_server);
            }

            profile.messageOne.setVisibility(TextView.VISIBLE);
            profile.messageOne.setText(result);

            profile.messageThree.setVisibility(TextView.VISIBLE);
            profile.messageThree.setText(result);

            if (result.equals(Constants.PUBLIC_KEY_SAVED)) {

                profile.messageTwo.setVisibility(TextView.VISIBLE);
                profile.messageTwo.setText(profile.getString(R.string.touch_menu_button));

                profile.messageFour.setVisibility(TextView.VISIBLE);
                profile.messageFour.setText(profile.getString(R.string.touch_menu_button));

                ((WebAuthnPlus) profile.getApplication()).setSignOnSuccessful(true);

                /*
                 *  With the publick key saved, the user is created.
                 */
                SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(profile);
                Editor prefEditor = sharedPreferences.edit();
                prefEditor.putString(profile.getString(R.string.user_created_key), profile.getString(R.string.user_created));
                prefEditor.apply();

                log("User Created");
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessRetrieveTransactionUuid extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<Profile> activityReference;

        // only retain a weak reference to the activity
        ProcessRetrieveTransactionUuid(Profile context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            Profile profile = activityReference.get();

            if (!profile.isNetworkAvailable()) {
                return profile.getString(R.string.network_unavailable);
            } else {

                String targetUrlString = urlStrings[0];
                String urlParameters = urlStrings[1];
                String transferKeyHex = urlStrings[2];

                URL targetUrl;
                HttpURLConnection connection = null;

                try {
                    targetUrl = new URL(targetUrlString);

                    connection = (HttpURLConnection) targetUrl.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    String responseString = CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, profile);
                    return Utilities.parseNameValuePairs(responseString, Constants.TRANSACTION_UUID);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            Profile profile = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            profile.progressDialog = new ProgressDialog(profile);
            profile.progressDialog.setCancelable(true);
            profile.progressDialog.setTitle(profile.getString(R.string.app_name));
            profile.progressDialog.setMessage(profile.getString(R.string.retrieving_transaction_uuid));
            profile.progressDialog.setIndeterminate(false);
            profile.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            profile.progressDialog.setProgress(0);
            profile.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String transactionUuid) {

            Profile profile = activityReference.get();

            log("RESULT::" + transactionUuid + "::");

            profile.progressDialog.dismiss();

            String[] paramStrings = CryptoUtilities.generateParams_UpdateUser(profile.userSecurityKeyHex, transactionUuid, profile.sharedPreferences, profile);

            assert paramStrings != null;
            String urlParameters = paramStrings[0];
            String transferKeyHex = paramStrings[1];

            String[] urlStrings = {Constants.UPDATE_USER_URL, urlParameters, transferKeyHex};

            ProcessUpdateUser processUpdateUser = new ProcessUpdateUser(profile);
            processUpdateUser.execute(urlStrings);
        }
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    private static class ProcessUpdateUser extends AsyncTask<String, Void, String> {

        /*
         * Thx Suragch
         * https://stackoverflow.com/questions/44309241/warning-this-asynctask-class-should-be-static-or-leaks-might-occur
         */
        private final WeakReference<Profile> activityReference;

        // only retain a weak reference to the activity
        ProcessUpdateUser(Profile context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected String doInBackground(String... urlStrings) {

            Profile profile = activityReference.get();

            if (!profile.isNetworkAvailable()) {
                return profile.getString(R.string.network_unavailable);
            } else {

                String targetURL = urlStrings[0];
                String urlParameters = urlStrings[1];
                String transferKeyHex = urlStrings[2];

                URL url;
                HttpURLConnection connection = null;

                try {
                    url = new URL(targetURL);

                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    connection.setRequestProperty("Content-Length", "" + urlParameters.getBytes().length);
                    connection.setRequestProperty("Content-Language", "en-US");

                    connection.setUseCaches(false);
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    // Send request
                    DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
                    dataOutputStream.writeBytes(urlParameters);
                    dataOutputStream.flush();
                    dataOutputStream.close();

                    // Get Response
                    InputStream inputStream = connection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String line;
                    StringBuilder response = new StringBuilder();

                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }

                    bufferedReader.close();

                    return CryptoUtilities.decryptResponseString(response.toString().trim(), transferKeyHex, profile);

                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        }

        // ----------------------------------------------------------------------------------------------------------------

        protected void onPreExecute() {

            Profile profile = activityReference.get();

            /*
             * Start up a ProgressDialog.STYLE_SPINNER when the asynch request begins.
             * Note:  Because the network connection is so fast, this ProgressDialog is rarely seen.
             */
            profile.progressDialog = new ProgressDialog(profile);
            profile.progressDialog.setCancelable(false);
            profile.progressDialog.setTitle(profile.getString(R.string.app_name));
            profile.progressDialog.setMessage(profile.getString(R.string.updating));
            profile.progressDialog.setIndeterminate(false);
            profile.progressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            profile.progressDialog.setProgress(0);
            profile.progressDialog.show();
        }

        // ----------------------------------------------------------------------------------------------------------------

        @Override
        protected void onPostExecute(String result) {

            Profile profile = activityReference.get();

            log("RESULT::" + result + "::");

            profile.progressDialog.dismiss();

            if (result == null) {
                result = profile.getString(R.string.problem_with_authentication_server);
            }

            profile.messageOne.setVisibility(TextView.VISIBLE);
            profile.messageOne.setText(result);

            profile.messageThree.setVisibility(TextView.VISIBLE);
            profile.messageThree.setText(result);

            if (result.equals(Constants.PROFILE_UPDATED)) {

                profile.messageTwo.setVisibility(TextView.VISIBLE);
                profile.messageTwo.setText(profile.getString(R.string.touch_menu_button));

                profile.messageFour.setVisibility(TextView.VISIBLE);
                profile.messageFour.setText(profile.getString(R.string.touch_menu_button));
            }
        }
    }
}















