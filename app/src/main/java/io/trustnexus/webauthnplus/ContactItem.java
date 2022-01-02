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

import androidx.annotation.NonNull;

public class ContactItem implements Comparable<ContactItem> {

  private String contactId;
  private String displayName;
  private String phoneNumber;
  private String emailAddress;

  // ------------------------------------------------------------------------------------------------------------------

  ContactItem() {
  }

  // ------------------------------------------------------------------------------------------------------------------

  String getContactId() {
    return contactId;
  }

  void setContactId(String contactId) {
    this.contactId = contactId;
  }

  // ------------------------------------------------------------------------------------------------------------------

  String getDisplayName() {
    return displayName;
  }

  void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  // ------------------------------------------------------------------------------------------------------------------

  String getPhoneNumber() {
    return phoneNumber;
  }

  void setPhoneNumber(String phoneNumber) {
    this.phoneNumber = phoneNumber;
  }

  // ------------------------------------------------------------------------------------------------------------------

  String getEmailAddress() {
    return emailAddress;
  }

  void setEmailAddress(String emailAddress) {
    this.emailAddress = emailAddress;
  }

  // ------------------------------------------------------------------------------------------------------------------

  @Override
  public int compareTo(@NonNull ContactItem contactItem) {
    return this.getDisplayName().compareTo(contactItem.getDisplayName());
  }
}







