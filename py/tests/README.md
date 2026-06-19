# Python verifier tests

Offline unit tests for the helpers in `py/model_verifier.py`. No network calls —
TDX-quote verification (dcap-qvl) and GPU attestation (NRAS) are intentionally
out of scope here.

## Running

```bash
pip install -r requirements.txt
pip install pytest
pytest py/tests/
```

## Fixtures

`fixtures/nearai_cloud_report_openai_gpt_oss_120b.json` is a real attestation
bundle captured from `cloud-api.near.ai`. To recapture it (e.g. to refresh
after a gateway upgrade), run:

```bash
NONCE="deadbeef$(printf '%056d' 1)"
curl -sS "https://cloud-api.near.ai/v1/attestation/report?model=openai/gpt-oss-120b&nonce=${NONCE}&signing_algo=ecdsa" \
  -o py/tests/fixtures/nearai_cloud_report_openai_gpt_oss_120b.json
```

The tests pin the deterministic parts of the bundle (field shape,
`report_data` binding to `signing_address` and `request_nonce`). They do not
re-verify the Intel quote against PCCS or the GPU evidence against NRAS.
