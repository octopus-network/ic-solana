use candid::Principal;
use ic_management_canister_types::{
    DerivationPath, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs, SchnorrPublicKeyResponse,
    SignWithSchnorrArgs, SignWithSchnorrReply,
};
use serde_bytes::ByteBuf;

/// Signs a message with an ed25519 key.
pub async fn sign_with_eddsa(
    schnorr_canister_id: Principal,
    key_name: String,
    derivation_path: Vec<ByteBuf>,
    message: Vec<u8>,
) -> Vec<u8> {
    let schnorr_canister = schnorr_canister_id;
    let res: Result<(SignWithSchnorrReply,), _> = ic_cdk::api::call::call_with_payment(
        schnorr_canister,
        "sign_with_schnorr",
        (SignWithSchnorrArgs {
            message,
            derivation_path: DerivationPath::new(derivation_path),
            key_id: SchnorrKeyId {
                name: key_name,
                algorithm: SchnorrAlgorithm::Ed25519,
            },
        },),
        25_000_000_000,
    )
    .await;

    res.unwrap().0.signature
}

/// Fetches the ed25519 public key from the schnorr canister.
pub async fn eddsa_public_key(
    schnorr_canister_id: Principal,
    key_name: String,
    derivation_path: Vec<ByteBuf>,
) -> Vec<u8> {
    let schnorr_canister = schnorr_canister_id;
    let res: Result<(SchnorrPublicKeyResponse,), _> = ic_cdk::call(
        schnorr_canister,
        "schnorr_public_key",
        (SchnorrPublicKeyArgs {
            canister_id: None,
            derivation_path: DerivationPath::new(derivation_path),
            key_id: SchnorrKeyId {
                algorithm: SchnorrAlgorithm::Ed25519,
                name: key_name,
            },
        },),
    )
    .await;

    res.unwrap().0.public_key
}
