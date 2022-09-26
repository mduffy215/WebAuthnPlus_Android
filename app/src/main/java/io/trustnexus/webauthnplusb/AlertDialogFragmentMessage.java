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

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.os.Bundle;
import android.view.View;

import androidx.core.content.ContextCompat;

import io.trustnexus.webauthnplusb.util.Constants;

public class AlertDialogFragmentMessage extends DialogFragment {

    public AlertDialogFragmentMessage() {
        super();
    }

    public static AlertDialogFragmentMessage newInstance(int dialogType) {
        AlertDialogFragmentMessage alertDialogFragmentMessage = new AlertDialogFragmentMessage();
        Bundle args = new Bundle();
        args.putInt("dialogType", dialogType);
        alertDialogFragmentMessage.setArguments(args);
        return alertDialogFragmentMessage;
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        int dialogType = getArguments().getInt("dialogType");

        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setCancelable(false);
        builder.setPositiveButton(R.string.ok, null);

        switch (dialogType) {
            case Constants.PASSWORD_VERIFICATION_FAILED:
                builder.setTitle(R.string.app_activation);
                builder.setMessage(R.string.password_verification_failed);
                break;
            case Constants.INCOMPLETE_PROFILE:
                builder.setTitle(R.string.incomplete_profile);
                builder.setMessage(R.string.profile_requirements);
                break;
            case Constants.MAX_IDLE_TIME_EXCEEDED:
                builder.setTitle(R.string.application_timeout);
                builder.setMessage(R.string.max_idle_time_exceeded);
                break;
            case Constants.INSUFFICIENT_CONTACT_INFORMATION:
                builder.setTitle(R.string.update_contacts);
                builder.setMessage(R.string.contacts_requirements);
                break;
            default:
                builder.setMessage("");
        }

        AlertDialog alertDialog = builder.show();

        // Surprisingly, the title divider cannot be styled through XML.
        int titleDividerId = getResources().getIdentifier("titleDivider", "id", "android");

        View titleDivider = alertDialog.findViewById(titleDividerId);

        if (titleDivider != null) {
            titleDivider.setBackgroundColor(ContextCompat.getColor(getActivity(), R.color.primary_color));
        }

        return alertDialog;
    }
}







