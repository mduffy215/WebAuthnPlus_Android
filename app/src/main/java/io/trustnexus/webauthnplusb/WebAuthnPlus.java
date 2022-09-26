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

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.util.Log;

import io.trustnexus.webauthnplusb.util.Constants;

/*
 * The userSecurityKeyHex is retrieved from the mobile application provider's server during the sign on process to the
 * mobile app.  This key is used to encrypt/decrypt values in the WebAuthnPlus application, most significantly the user's
 * private key which is stored on the user's device in an encrypted state.  For security reasons we definitely do not
 * want to store the userSecurityKeyHex in SharedPreferences at any time.
 *
 * We could pass the value around in the Extras Bundle of the Intents; however, Firebase messaging breaks that process.
 *
 * There is some debate regarding the wisdom of storing application scope values in an extension of the Application
 * object:
 *
 * Don't Store Data in the Application Object
 * http://www.developerphil.com/dont-store-data-in-the-application-object/
 *
 * and
 *
 * Android global variable
 * https://stackoverflow.com/questions/1944656/android-global-variable
 *
 * The main problem is throwing an NPE after, "Android silently kills the app to reclaim some memory."  This can occur
 * if the values are not re-initialized; however, we re-initialize the userSecurityKeyHex at every startup and
 * other variables as we need them.  There is no possibility that this architecture will result in an NPE.
 *
 * If you are using extras to pass variables around to your intents, this architecture will make your code far more
 * elegant.
 */
public class WebAuthnPlus extends Application {

    private Boolean signOnSuccessful = false;

    private String passwordValue;
    private String userSecurityKeyHex;

    private String credentialProviderName;
    private String domainName;
    private String authenticationCode;
    private String sessionUuid;

    private byte[] credentialIconByteArray;
    private String createCredentialType;
    private String credentialUuid;
    private String createCredentialResult;
    private String verificationCodeValue;
    private String lastSignOnCredentialType;

    private String firebaseDataEncryptedHex;
    private String firebaseDataEncryptedHashedHex;

    private String senderCredentialType;
    private String recipientDisplayName;
    private String recipientPhoneNumber;
    private String recipientEmailAddress;

    private String smsSender;
    private String smsRef;

    private Long lastInteraction = 0L;

    private static String currentActivity;

    private final static boolean DEBUG = true;

    // ------------------------------------------------------------------------------------------------------------------

    public void onCreate() {
        super.onCreate();
        registerActivityLifecycleCallbacks(new WebAuthnPlusLifecycleCallbacks());
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

    public Boolean getSignOnSuccessful() {
        return signOnSuccessful;
    }

    public void setSignOnSuccessful(Boolean signOnSuccessful) {
        this.signOnSuccessful = signOnSuccessful;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getPasswordValue() {
        return passwordValue;
    }

    public void setPasswordValue(String passwordValue) {
        this.passwordValue = passwordValue;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getUserSecurityKeyHex() {
        return userSecurityKeyHex;
    }

    public void setUserSecurityKeyHex(String userSecurityKeyHex) {
        this.userSecurityKeyHex = userSecurityKeyHex;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getCredentialProviderName() {
        return credentialProviderName;
    }

    public void setCredentialProviderName(String credentialProviderName) {
        this.credentialProviderName = credentialProviderName;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getLastSignOnCredentialType() {
        return lastSignOnCredentialType;
    }

    public void setLastSignOnCredentialType(String lastSignOnCredentialType) {
        this.lastSignOnCredentialType = lastSignOnCredentialType;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public byte[] getCredentialIconByteArray() {
        return credentialIconByteArray;
    }

    public void setCredentialIconByteArray(byte[] credentialIconByteArray) {
        this.credentialIconByteArray = credentialIconByteArray;
    }

// ------------------------------------------------------------------------------------------------------------------

    public String getCreateCredentialType() {
        return createCredentialType;
    }

    public void setCreateCredentialType(String createCredentialType) {
        this.createCredentialType = createCredentialType;
    }

// ------------------------------------------------------------------------------------------------------------------

    public String getCredentialUuid() {
        return credentialUuid;
    }

    public void setCredentialUuid(String credentialUuid) {
        this.credentialUuid = credentialUuid;
    }
// ------------------------------------------------------------------------------------------------------------------

    public String getCreateCredentialResult() {
        return createCredentialResult;
    }

    public void setCreateCredentialResult(String createCredentialResult) {
        this.createCredentialResult = createCredentialResult;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getAuthenticationCode() {
        return authenticationCode;
    }

    public void setAuthenticationCode(String authenticationCode) {
        this.authenticationCode = authenticationCode;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getSessionUuid() {
        return sessionUuid;
    }

    public void setSessionUuid(String sessionUuid) {
        this.sessionUuid = sessionUuid;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getVerificationCodeValue() {
        return verificationCodeValue;
    }

    public void setVerificationCodeValue(String verificationCodeValue) {
        this.verificationCodeValue = verificationCodeValue;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getFirebaseDataEncryptedHex() {
        return firebaseDataEncryptedHex;
    }

    public void setFirebaseDataEncryptedHex(String firebaseDataEncryptedHex) {
        this.firebaseDataEncryptedHex = firebaseDataEncryptedHex;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getFirebaseDataEncryptedHashedHex() {
        return firebaseDataEncryptedHashedHex;
    }

    public void setFirebaseDataEncryptedHashedHex(String firebaseDataEncryptedHashedHex) {
        this.firebaseDataEncryptedHashedHex = firebaseDataEncryptedHashedHex;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getSenderCredentialType() {
        return senderCredentialType;
    }

    public void setSenderCredentialType(String senderCredentialType) {
        this.senderCredentialType = senderCredentialType;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getRecipientDisplayName() {
        return recipientDisplayName;
    }

    public void setRecipientDisplayName(String recipientDisplayName) {
        this.recipientDisplayName = recipientDisplayName;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getRecipientPhoneNumber() {
        return recipientPhoneNumber;
    }

    public void setRecipientPhoneNumber(String recipientPhoneNumber) {
        this.recipientPhoneNumber = recipientPhoneNumber;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getRecipientEmailAddress() {
        return recipientEmailAddress;
    }

    public void setRecipientEmailAddress(String recipientEmailAddress) {
        this.recipientEmailAddress = recipientEmailAddress;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getSmsSender() {
        return smsSender;
    }

    public void setSmsSender(String smsSender) {
        this.smsSender = smsSender;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getSmsRef() {
        return smsRef;
    }

    public void setSmsRef(String smsRef) {
        this.smsRef = smsRef;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public Long getLastInteraction() {
        return lastInteraction;
    }

    public void setLastInteraction(Long lastInteraction) {
        this.lastInteraction = lastInteraction;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public void setExitValues() {

        this.signOnSuccessful = null;
        this.passwordValue = null;
        this.userSecurityKeyHex = null;

        this.credentialProviderName = null;
        this.domainName = null;
        this.authenticationCode = null;
        this.sessionUuid = null;

        this.credentialIconByteArray = null;
        this.createCredentialType = null;
        this.createCredentialResult = null;
        this.verificationCodeValue = null;
        this.lastSignOnCredentialType = null;

        this.lastInteraction = 0L;
    }

    // ------------------------------------------------------------------------------------------------------------------

    public String getCurrentActivity() {
        return currentActivity;
    }

    public static void setCurrentActivity(String newCurrentActivity) {
        currentActivity = newCurrentActivity;
    }

    // ------------------------------------------------------------------------------------------------------------------

    /*
     * You would think that determining the current activity would be a simple process, but it is not.
     *
     * Thx to:  nory kaname (baroqueworksdev)
     * http://baroqueworksdev.blogspot.in/2012/12/how-to-use-activitylifecyclecallbacks.html
     */
    private static final class WebAuthnPlusLifecycleCallbacks implements ActivityLifecycleCallbacks {

        public void onActivityCreated(Activity activity, Bundle bundle) {
            log("onActivityCreated:" + activity.getLocalClassName());
            WebAuthnPlus.setCurrentActivity(activity.getLocalClassName());
        }

        public void onActivityDestroyed(Activity activity) {
            log("onActivityDestroyed:" + activity.getLocalClassName());
        }

        public void onActivityPaused(Activity activity) {
            log("onActivityPaused:" + activity.getLocalClassName());
        }

        public void onActivityResumed(Activity activity) {
            log("onActivityResumed:" + activity.getLocalClassName());
            WebAuthnPlus.setCurrentActivity(activity.getLocalClassName());
        }

        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
            log("onActivitySaveInstanceState:" + activity.getLocalClassName());
        }

        public void onActivityStarted(Activity activity) {
            log("onActivityStarted:" + activity.getLocalClassName());
        }

        public void onActivityStopped(Activity activity) {
            log("onActivityStopped:" + activity.getLocalClassName());
        }
    }

}















