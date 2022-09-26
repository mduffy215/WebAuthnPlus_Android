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

package io.trustnexus.webauthnplusb.util;

import android.text.Editable;
import android.text.TextWatcher;
import android.widget.EditText;

import java.text.NumberFormat;

/*
 * Thx to Guilherme Oliveira!
 * https://stackoverflow.com/questions/5107901/better-way-to-format-currency-input-edittext
 */
public class NumberTextWatcher implements TextWatcher {
    private final EditText editText;
    private String current = "";

    public NumberTextWatcher(EditText editText) {
        this.editText = editText;
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void afterTextChanged(Editable editable) {
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
    }

    // ------------------------------------------------------------------------------------------------------------------

    @Override
    public void onTextChanged(CharSequence s, int start, int before, int count) {
        if (!s.toString().equals(current)) {
            editText.removeTextChangedListener(this);

            String cleanString = s.toString().replaceAll("[$,.]", "");

            double parsed = Double.parseDouble(cleanString);
            String formatted = NumberFormat.getCurrencyInstance().format((parsed / 100));

            current = formatted;
            editText.setText(formatted);
            editText.setSelection(formatted.length());

            editText.addTextChangedListener(this);
        }
    }
}
