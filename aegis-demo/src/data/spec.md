# Spec

Labeled the demo records as synthetic data for hackathon rule 11.1.

- `mock.ts` exports `DATA_CLASSIFICATION = "synthetic"` and states that the analyses are synthetic or simulated data.
- `sample.json` sets `data_classification` to `synthetic`.

`backend/src/test_data_policy.py` checks that both labels are present.
