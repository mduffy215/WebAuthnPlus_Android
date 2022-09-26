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
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.Context;
import android.os.Bundle;
import android.view.View;

import androidx.core.content.ContextCompat;

public class AlertDialogFragmentDeleteCredential extends DialogFragment {

    public AlertDialogFragmentDeleteCredential() {
        super();
    }

    private OnDeleteCredentialListener onDeleteCredentialListener;

    public static AlertDialogFragmentDeleteCredential newInstance(int credentialId) {
        AlertDialogFragmentDeleteCredential frag = new AlertDialogFragmentDeleteCredential();
        Bundle args = new Bundle();
        args.putInt("credentialId", credentialId);
        frag.setArguments(args);
        return frag;
    }

    // ------------------------------------------------------------------------------------------------------------------

    //ref:  http://developer.android.com/guide/components/fragments.html#CommunicatingWithActivity

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);

        // https://stackoverflow.com/questions/32083053/android-fragment-onattach-deprecated
        Activity activity = null;

        if (context instanceof Activity) {
            activity = (Activity) context;
        }

        try {
            onDeleteCredentialListener = (OnDeleteCredentialListener) activity;
        } catch (ClassCastException e) {
            throw new ClassCastException(activity + " must implement OnArticleSelectedListener");
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {

        final int credentialId = getArguments().getInt("credentialId");

        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setTitle(R.string.delete_credential);
        builder.setMessage(R.string.are_you_sure);
        builder.setCancelable(true);
        builder.setNegativeButton(R.string.no, null);
        builder.setPositiveButton(R.string.yes,
                (dialog, arrayValue) -> onDeleteCredentialListener.onDeleteCredential(getString(R.string.yes), credentialId));

        AlertDialog alertDialog = builder.show();

        /* Surprisingly, the title divider cannot be styled through XML.*/
        int titleDividerId = getResources().getIdentifier("titleDivider", "id", "android");
        View titleDivider = alertDialog.findViewById(titleDividerId);
        if (titleDivider != null) {
            titleDivider.setBackgroundColor(ContextCompat.getColor(getActivity(), R.color.primary_color));
        }

        return alertDialog;
    }

    // ------------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------------

    //ref:  http://developer.android.com/guide/components/fragments.html#CommunicatingWithActivity

    // Container Activity must implement this interface
    public interface OnDeleteCredentialListener {
        void onDeleteCredential(String areYouSure, int credentialId);
    }
}







