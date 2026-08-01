# Test data

`cvss_lookup.json` — the 270-entry CVSS v4.0 macrovector lookup table, converted
from `cvss_lookup.js` in FIRST's reference calculator:

    https://github.com/FIRSTdotorg/cvss-v4-calculator

    Copyright FIRST, Red Hat, and contributors
    SPDX-License-Identifier: BSD-2-Clause

It is vendored as data rather than fetched, because it IS the specification's
scoring table — there is no formula to derive it from — and a scanner that
reaches the network to decide a severity is not one that runs offline (D14).

`v3-expected.tsv` and `v4-expected.tsv` are expected scores for the vectors our
own database holds, not transcriptions of anyone's output format: the vectors
come from the live database and the scores from an independent implementation
(RedHat's `cvss` Python library for v3, FIRST's reference calculator for v4).
Selection is by the vector's own prefix, never by the record's declared type —
one live record files a `CVSS:3.1` vector under `CVSS_V4`.
