# OPTEE Trusted Application: OX05B1S camera frame HMAC authentication.
## Security model

The Pre-Provisioned Key (PPK) is stored exclusively inside OPTEE persistent
secure storage and never crosses the world boundary.  Only two derived
values ever leave the secure world:

* `SR2H` – a single 32-bit row index (cannot reconstruct the key).
* A boolean valid/invalid result for each frame.

Key derivation and all cryptographic operations are performed by the TEE
crypto API (GP TEE Internal Core API §6).  The HMAC comparison uses
constant-time byte equality to prevent timing side-channels.

## Commands

| ID | Name          | Description                                         |
|----|---------------|-----------------------------------------------------|
|  1 | ProvisionKey  | Store the 32-byte PPK (manufacturing / provisioning)|
|  2 | GetRowStart   | Derive and return the per-frame `SR2H` row index    |
|  3 | VerifyHmac    | Verify the frame HMAC; returns bool only            |
|  4 | Version       | Return the TA version string                        |