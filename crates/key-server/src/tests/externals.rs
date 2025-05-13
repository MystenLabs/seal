// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::externals::current_epoch_time;
use crate::signed_message::signed_request;
use crate::valid_ptb::ValidPtb;
use crate::{
    signed_message,
    types::{ElGamalPublicKey, ElgamalVerificationKey},
    Certificate, Server,
};
use crypto::elgamal;
use fastcrypto::ed25519::Ed25519Signature;
use fastcrypto::traits::{KeyPair, Signer};
use fastcrypto::{ed25519::Ed25519KeyPair, error::FastCryptoResult, groups::bls12381::G1Element};
use rand::thread_rng;
use shared_crypto::intent::{Intent, IntentMessage, PersonalMessage};
use sui_types::{
    base_types::ObjectID, crypto::Signature, signature::GenericSignature,
    transaction::ProgrammableTransaction,
};

pub(super) fn sign(
    pkg_id: &ObjectID,
    ptb: &ProgrammableTransaction,
    eg_pk: &ElGamalPublicKey,
    eg_vk: &ElgamalVerificationKey,
    kp: &Ed25519KeyPair,
    creation_time: u64,
    ttl_min: u16,
) -> (Certificate, Ed25519Signature) {
    // We use the same eddsa keypair for both the certificate and the request signature

    // create the cert
    let msg_to_sign = signed_message::signed_message(pkg_id, kp.public(), creation_time, ttl_min);
    let personal_msg = PersonalMessage {
        message: msg_to_sign.as_bytes().to_vec(),
    };
    let msg_with_intent = IntentMessage::new(Intent::personal_message(), personal_msg.clone());
    let cert_sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, kp));
    let cert = Certificate {
        user: kp.public().into(),
        session_vk: kp.public().clone(),
        creation_time,
        ttl_min,
        signature: cert_sig,
    };
    // session sig
    let signed_msg = signed_request(ptb, eg_pk, eg_vk);
    let request_sig = kp.sign(&signed_msg);
    (cert, request_sig)
}

pub(crate) async fn get_key(
    server: &Server,
    pkg_id: &ObjectID,
    ptb: ProgrammableTransaction,
    kp: &Ed25519KeyPair,
) -> FastCryptoResult<G1Element> {
    let (sk, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(pkg_id, &ptb, &pk, &vk, kp, current_epoch_time(), 1);
    server
        .check_request(
            &ValidPtb::try_from(ptb).unwrap(),
            &pk,
            &vk,
            &req_sig,
            &cert,
            1000,
            None,
            None,
        )
        .await
        .map(|ids| {
            elgamal::decrypt(
                &sk,
                &server.create_response(&ids, &pk).decryption_keys[0].encrypted_key,
            )
        })
        .map_err(|_| fastcrypto::error::FastCryptoError::GeneralOpaqueError)
}
