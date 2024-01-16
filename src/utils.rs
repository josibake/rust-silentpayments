use crate::Error;
use bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine, hash160};
use secp256k1::{
    PublicKey,
    Parity::Even,
    Scalar,
    XOnlyPublicKey,
};

pub mod receiving;
pub mod sending;

sha256t_hash_newtype! {
    pub struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub struct InputsHash(_);

    pub struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub struct LabelHash(_);

    pub struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub struct SharedSecretHash(_);
}

// Define OP_CODES used in script template matching for readability
const OP_1: u8 = 0x51;
const OP_0: u8 = 0x00;
const OP_PUSHBYTES_20: u8 = 0x14;
const OP_PUSHBYTES_32: u8 = 0x20;
const OP_HASH160: u8 = 0xA9;
const OP_EQUAL: u8 = 0x87;
const OP_DUP: u8 = 0x76;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xAC;
const COMPRESSED_PUBKEY_SIZE: usize = 33;

pub struct VinData {
    pub script_sig: Vec<u8>,
    pub txinwitness: Vec<Vec<u8>>,
    pub prevout: Vec<u8>,
}

// script templates for inputs allowed in BIP352 shared secret derivation
pub fn is_p2tr(spk: &[u8]) -> bool {
    matches!(spk, [OP_1, OP_PUSHBYTES_32, ..] if spk.len() == 34)
}

fn is_p2wpkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_0, OP_PUSHBYTES_20, ..] if spk.len() == 22)
}

fn is_p2sh(spk: &[u8]) -> bool {
    matches!(spk, [OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUAL] if spk.len() == 23)
}

fn is_p2pkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_DUP, OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUALVERIFY, OP_CHECKSIG] if spk.len() == 25)
}

pub fn get_A_sum_public_keys(input: &Vec<PublicKey>) -> PublicKey {
    let keys_refs: &Vec<&PublicKey> = &input.iter().collect();

    PublicKey::combine_keys(keys_refs).unwrap()
}

pub fn get_pubkey_from_input(vin: &VinData) -> Result<PublicKey, Error> {
    if is_p2pkh(&vin.prevout) {
        let spk_hash = &vin.prevout[3..23];
        for i in (COMPRESSED_PUBKEY_SIZE..=vin.script_sig.len()).rev() {
            let pubkey_bytes = &vin.script_sig[i - COMPRESSED_PUBKEY_SIZE..i];
            let pubkey_hash = hash160::Hash::hash(pubkey_bytes);
            if pubkey_hash.to_byte_array() == spk_hash {
                return Ok(PublicKey::from_slice(pubkey_bytes)?);
            }
        }
    } else if is_p2sh(&vin.prevout) {
        let redeem_script = &vin.script_sig[1..];
        if is_p2wpkh(redeem_script) {
            let len = redeem_script.len();
            return Ok(PublicKey::from_slice(&redeem_script[len - COMPRESSED_PUBKEY_SIZE..len])?);
        }
    } else if is_p2wpkh(&vin.prevout) {
        return Ok(PublicKey::from_slice(vin.txinwitness.last().unwrap())?);
    } else if is_p2tr(&vin.prevout) {
        let x_only_public_key = XOnlyPublicKey::from_slice(&vin.prevout[2..34]).unwrap();
        return Ok(PublicKey::from_x_only_public_key(x_only_public_key, Even));
    }
    return Err(Error::PublicKeyNotFound("Public key not found".to_string()));
}

pub fn hash_outpoints(sending_data: &Vec<(String, u32)>, A_sum: PublicKey) -> Result<Scalar, Error> {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    for outpoint in sending_data {
        let mut bytes: Vec<u8> = hex::decode(outpoint.0.as_str())?;

        // txid in string format is big endian and we need little endian
        bytes.reverse();
        bytes.extend_from_slice(&outpoint.1.to_le_bytes());
        outpoints.push(bytes);
    }

    // sort outpoints
    outpoints.sort();

    let smallest_outpoint = outpoints.first().unwrap();
    let mut eng = InputsHash::engine();
    eng.input(&smallest_outpoint);
    eng.input(&A_sum.serialize());

    Ok(Scalar::from_be_bytes(
        InputsHash::from_engine(eng).to_byte_array(),
    )?)
}
