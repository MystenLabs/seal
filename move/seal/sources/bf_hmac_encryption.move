// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Implementation of decryption for Seal using Boneh-Franklin over BLS12-381 as KEM and Hmac256Ctr as DEM.
module seal::bf_hmac_encryption;

use seal::{hmac256ctr, kdf::kdf, key_server::KeyServer, polynomial};
use sui::{
    bls12381::{
        G1,
        G2,
        Scalar,
        pairing,
        g2_from_bytes,
        hash_to_g1,
        g2_generator,
        scalar_from_bytes,
        g1_mul,
        g2_mul
    },
    group_ops::Element,
    hmac::hmac_sha3_256
};

const DST: vector<u8> = b"SUI-SEAL-IBE-BLS12381-00";
const DST_LENGTH: u8 = 24;

public struct EncryptedObject has copy, drop, store {
    package_id: address,
    id: vector<u8>,
    indices: vector<u8>,
    services: vector<address>,
    threshold: u8,
    nonce: Element<G2>,
    encrypted_shares: vector<vector<u8>>,
    encrypted_randomness: vector<u8>,
    blob: vector<u8>,
    aad: Option<vector<u8>>,
    mac: vector<u8>,
}

public struct VerifiedDerivedKey has drop, store {
    derived_key: Element<G1>,
    package_id: address,
    id: vector<u8>,
    key_server: ID,
}

public struct PublicKey has drop {
    key_server: ID,
    pk: Element<G2>,
}

public fun get_public_key(key_server: &KeyServer): PublicKey {
    PublicKey {
        key_server: object::id(key_server),
        pk: key_server.pk_as_bf_bls12381(),
    }
}

/// Decrypts an encrypted object using the given verified derived keys.
///
/// Call `verify_derived_keys` to verify derived keys before calling this function.
///
/// Aborts if there are not enough verified derived keys.
/// Aborts if any of the key servers are not among the key servers found in the encrypted object.
///
/// If the decryption fails, e.g. the AAD or MAC is invalid, the function returns `none`.
public fun decrypt(
    encrypted_object: &EncryptedObject,
    verified_derived_keys: &vector<VerifiedDerivedKey>,
    public_keys: &vector<PublicKey>,
): Option<vector<u8>> {
    let EncryptedObject {
        threshold,
        package_id,
        id,
        nonce,
        blob,
        mac,
        aad,
        indices,
        encrypted_shares,
        encrypted_randomness,
        services,
    } = encrypted_object;
    assert!(verified_derived_keys.length() >= *threshold as u64);
    assert!(verified_derived_keys.all!(|vdk| vdk.package_id == *package_id && vdk.id == *id));

    // Verify that the public keys are from the key servers in the encrypted object and in the same order.
    public_keys.zip_do_ref!(services, |a, b| assert!(a.key_server.to_address() == b));

    // Find the indices of the key servers corresponsing to the derived keys.
    let given_indices = verified_derived_keys.map_ref!(
        |vdk| services.find_index!(|service| vdk.key_server.to_address() == service).extract(),
    );

    // Create the full ID for the IBE scheme.
    let full_id = create_full_id(*package_id, *id);

    // Decrypt shares.
    let decrypted_shares = given_indices.zip_map_ref!(verified_derived_keys, |i, vdk| {
        let symmetric_key = kdf(
            &pairing(&vdk.derived_key, nonce),
            nonce,
            &hash_to_g1(&full_id),
            services[*i],
            indices[*i] as u8,
        );
        encrypted_shares[*i].zip_map!(symmetric_key, |a, b| a ^ b)
    });

    // Construct the key from the decrypted shares.
    let share_indices = given_indices.map!(|i| indices[i]);
    let polynomials = vector::tabulate!(
        32,
        |i| polynomial::interpolate(&share_indices, &decrypted_shares.map_ref!(|share| share[i])),
    );
    assert!(polynomials.all!(|p| p.degree() + 1 == *threshold as u64));
    let base_key = polynomials.map_ref!(|p| p.get_constant_term());

    // The encryption randomness can now be decrypted and used to decrypt the rest of the shares.
    let randomness = scalar_from_bytes(
        &xor(encrypted_randomness, &derive_key(KeyPurpose::EncryptedRandomness, &base_key)),
    );
    assert!(nonce == g2_mul(&randomness, &g2_generator()));
    let (remaining_shares, remaining_indices) = decrypt_shares_with_randomness(
        &randomness,
        encrypted_shares,
        &public_keys.map_ref!(|pk| pk.pk),
        services,
        &full_id,
        indices,
        &given_indices,
    );

    // Verify the consistency of the shares, eg. that they are all consistent with the polynomial interpolated from the shares decrypted from the given keys.
    remaining_shares.zip_do!(remaining_indices, |share, index| {
        verify_share(&polynomials, &share, index);
    });

    // Decrypt the blob.
    hmac256ctr::decrypt(
        blob,
        mac,
        &aad.get_with_default(vector[]),
        &derive_key(KeyPurpose::DEM, &base_key),
    )
}

fun verify_share(polynomials: &vector<polynomial::Polynomial>, share: &vector<u8>, index: u8) {
    polynomials.zip_do_ref!(share, |p, s| {
        assert!(p.evaluate(index) == s);
    });
}

fun create_full_id(package_id: address, id: vector<u8>): vector<u8> {
    let mut full_id = vector::empty();
    full_id.push_back(DST_LENGTH);
    full_id.append(DST);
    full_id.append(package_id.to_bytes());
    full_id.append(id);
    full_id
}

/// An enum representing the different purposes of the derived key.
public enum KeyPurpose {
    EncryptedRandomness,
    DEM,
}

/// Derives a key for a specific purpose from the base key.
fun derive_key(purpose: KeyPurpose, key: &vector<u8>): vector<u8> {
    match (purpose) {
        KeyPurpose::EncryptedRandomness => hmac_sha3_256(key, &vector[0]),
        KeyPurpose::DEM => hmac_sha3_256(key, &vector[1]),
    }
}

fun xor(a: &vector<u8>, b: &vector<u8>): vector<u8> {
    a.zip_map_ref!(b, |a, b| *a ^ *b)
}

/// Decrypts shares with the given randomness.
/// Returns the decrypted shares and the indices of the shares that were decrypted.
fun decrypt_shares_with_randomness(
    randomness: &Element<Scalar>,
    encrypted_shares: &vector<vector<u8>>,
    public_keys: &vector<Element<G2>>,
    object_ids: &vector<address>,
    full_id: &vector<u8>,
    indices: &vector<u8>,
    indices_to_omit: &vector<u64>,
): (vector<vector<u8>>, vector<u8>) {
    let n = indices.length();
    assert!(n == encrypted_shares.length());
    assert!(n == public_keys.length());
    assert!(n == object_ids.length());

    let gid = hash_to_g1(full_id);
    let gid_r = g1_mul(randomness, &hash_to_g1(full_id));
    let mut decrypted_shares = vector::empty();
    let mut remaining_indices = vector::empty();

    let nonce = g2_mul(randomness, &g2_generator());
    n.do!(|i| {
        if (!indices_to_omit.contains(&(indices[i] as u64))) {
            decrypted_shares.push_back(
                xor(
                    &encrypted_shares[i],
                    &kdf(
                        &pairing(&gid_r, &public_keys[i]),
                        &nonce,
                        &gid,
                        object_ids[i],
                        indices[i] as u8,
                    ),
                ),
            );
            remaining_indices.push_back(indices[i]);
        }
    });

    (decrypted_shares, remaining_indices)
}

/// Returns a vector of `VerifiedDerivedKey`s, asserting that all derived_keys are valid for the given full ID and key servers.
/// Aborts if the number of key servers does not match the number of derived keys.
public fun verify_derived_keys(
    derived_keys: &vector<Element<G1>>,
    package_id: address,
    id: vector<u8>,
    public_keys: &vector<PublicKey>,
): vector<VerifiedDerivedKey> {
    assert!(public_keys.length() == derived_keys.length());
    let hash_of_full_id = hash_to_g1(&create_full_id(package_id, id));

    public_keys.zip_map_ref!(derived_keys, |vpk, derived_key| {
        assert!(verify_derived_key(derived_key, &hash_of_full_id, &vpk.pk));
        VerifiedDerivedKey {
            derived_key: *derived_key,
            key_server: vpk.key_server,
            package_id,
            id,
        }
    })
}

fun verify_derived_key(
    derived_key: &Element<G1>,
    hash_of_full_id: &Element<G1>,
    public_key: &Element<G2>,
): bool {
    pairing(derived_key, &g2_generator()) == pairing(hash_of_full_id, public_key)
}

/// Deserialize a BCS encoded EncryptedObject.
/// Fails if the version is not 0.
/// Fails if the object is not a valid EncryptedObject.
/// Fails if the encryption type is not Hmac256Ctr.
/// Fails if the KEM type is not Boneh-Franklin over BLS12-381.
public fun parse_encrypted_object(object: vector<u8>): EncryptedObject {
    let mut bcs = sui::bcs::new(object);

    let version = bcs.peel_u8();
    assert!(version == 0);

    let package_id = bcs.peel_address();
    let id = bcs.peel_vec_u8();

    // services is a vector of tuples of the form (address, u8).
    let mut services: vector<address> = vector::empty();
    let indices = bcs.peel_vec!(|service| {
        services.push_back(service.peel_address());
        service.peel_u8()
    });
    assert!(services.length() == indices.length());
    let threshold = bcs.peel_u8();

    let ibe_type = bcs.peel_enum_tag();
    assert!(ibe_type == 0);

    // nonce is an G2 element, which is 96 bytes.
    let nonce_bytes = peel_tuple_u8(&mut bcs, 96);
    let nonce = g2_from_bytes(&nonce_bytes);

    // Shares are 32 bytes.
    let encrypted_shares = bcs.peel_vec!(|share_bcs| peel_tuple_u8(share_bcs, 32));

    // Encrypted randomness is 32 bytes.
    let encrypted_randomness = peel_tuple_u8(&mut bcs, 32);

    // Move only supports Hmac256Ctr mode.
    let encryption_type = bcs.peel_enum_tag();
    assert!(encryption_type == 1);

    let blob = bcs.peel_vec_u8();
    let aad = bcs.peel_option!(|aad_bcs| aad_bcs.peel_vec_u8());

    // MAC is 32 bytes.
    let mac = peel_tuple_u8(&mut bcs, 32);

    EncryptedObject {
        package_id,
        id,
        services,
        indices,
        threshold,
        nonce,
        encrypted_shares,
        encrypted_randomness,
        blob,
        aad,
        mac,
    }
}

// TODO: If fixed length vectors are ever supported, we should use that instead.
fun peel_tuple_u8(bcs: &mut sui::bcs::BCS, length: u64): vector<u8> {
    vector::tabulate!(length, |_| bcs.peel_u8())
}

public fun package_id(self: &EncryptedObject): &address {
    &self.package_id
}

public fun id(self: &EncryptedObject): &vector<u8> {
    &self.id
}

public fun services(self: &EncryptedObject): &vector<address> {
    &self.services
}

public fun indices(self: &EncryptedObject): &vector<u8> {
    &self.indices
}

public fun threshold(self: &EncryptedObject): u8 {
    self.threshold
}

public fun nonce(self: &EncryptedObject): &Element<G2> {
    &self.nonce
}

public fun encrypted_shares(self: &EncryptedObject): &vector<vector<u8>> {
    &self.encrypted_shares
}

public fun encrypted_randomness(self: &EncryptedObject): &vector<u8> {
    &self.encrypted_randomness
}

public fun blob(self: &EncryptedObject): &vector<u8> {
    &self.blob
}

public fun aad(self: &EncryptedObject): &Option<vector<u8>> {
    &self.aad
}

public fun mac(self: &EncryptedObject): &vector<u8> {
    &self.mac
}

#[test]
fun test_parse_encrypted_object() {
    let encoded =
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96b7d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3fcdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a977b02008812277be43199222d173eed91b480ce4c8cda5aea008ef884e77c990311136486a7daf8e2d99c0389ae40319714ffef1212ffcb456f0de08a7fa1bb185c936f9efe86fb5e32232d5e433230d04b1f2b27614b3b5b13f04db7d5c3b995e7e02e036315d5a9515d050595ea15b326ebcd510baf50463afd6517b5895d0756e39878bd656bd98418df11556d1ced740c7f839d97b81ee60238b3221fb45adfb0a5d1e4aec4f777271e5674bd7ded20421aa929755426501ba8366e465f5ebb861722b2909e5ac2e8608abd885014f2fb6006dd5896ab76ea243dea0d6d6ff4c3396b010de6062eb2dcb2f86bca32f83c9301200000000000000000000000000000000000000000000000000000000000000001184b788b4f5168aff51c0e6da7e2970caa02386c4dc179666ef4c6296807cda9";

    let object = parse_encrypted_object(encoded);
    assert!(object.package_id == @0x0);
    assert!(
        object.services == vector[@0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96, @0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3, @0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97],
    );
    assert!(object.threshold == 2);
}

#[test]
fun test_seal_decrypt() {
    use sui::bls12381::{g1_from_bytes};
    use sui::test_scenario::{Self, next_tx, ctx};
    use seal::key_server::{create_v1, destroy_cap};
    use std::string;

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk0 =
        x"aeb258b9fb9a2f29f74eb0a1a895860bb1c6ba3f9ea7075366de159e4764413e9ec0597ac9c0dad409723935440a45f40eee4728630ae3ea40a68a819375bba1d78d7810f901d8a469d785d00cfed6bd28f01d41e49c5652d924e9d19fddcf62";
    let cap0 = create_v1(
        string::utf8(b"mysten0"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk0,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s0: KeyServer = test_scenario::take_shared(&scenario);

    let pk1 =
        x"b1076a26f4f82f39d0e767fcd2118659362afe40bce4e8d553258c86756bb74f888bca79f2d6b71edf6e25af89efa83713a223b48a19d2e551897ac92ac7458336cd489be3be025e348ca93f4c94d22594f96f0e08990e51a7de9da8ff29c98f";
    let cap1 = create_v1(
        string::utf8(b"mysten1"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk1,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s1: KeyServer = test_scenario::take_shared(&scenario);

    let pk2 =
        x"95fcb465af3791f31d53d80db6c8dcf9f83a419b2570614ecfbb068f47613da17cb9ffc66bb052b9546f17196929538f0bd2d38e1f515d9916e2db13dc43e0ccbd4cb3d7cbb13ffecc0b68b37481ebaaaa17cad18096a9c2c27a797f17d78623";
    let cap2 = create_v1(
        string::utf8(b"mysten2"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk2,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s2: KeyServer = test_scenario::take_shared(&scenario);

    // For reference, the encryption was created with the following CLI command:
    // cargo run --bin seal-cli encrypt-hmac --message 48656C6C6F2C20776F726C6421 --aad 0x0000000000000000000000000000000000000000000000000000000000000001 --package-id 0x0 --id 0x381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --threshold 2 aeb258b9fb9a2f29f74eb0a1a895860bb1c6ba3f9ea7075366de159e4764413e9ec0597ac9c0dad409723935440a45f40eee4728630ae3ea40a68a819375bba1d78d7810f901d8a469d785d00cfed6bd28f01d41e49c5652d924e9d19fddcf62 b1076a26f4f82f39d0e767fcd2118659362afe40bce4e8d553258c86756bb74f888bca79f2d6b71edf6e25af89efa83713a223b48a19d2e551897ac92ac7458336cd489be3be025e348ca93f4c94d22594f96f0e08990e51a7de9da8ff29c98f 95fcb465af3791f31d53d80db6c8dcf9f83a419b2570614ecfbb068f47613da17cb9ffc66bb052b9546f17196929538f0bd2d38e1f515d9916e2db13dc43e0ccbd4cb3d7cbb13ffecc0b68b37481ebaaaa17cad18096a9c2c27a797f17d78623 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    let encrypted_object =
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97030200b7f57f44e5302b684737612ebf4561ce4b4c5fea496731914f78d402db1c3c712fae396125a150e8eb1582e05a1f98140afc3214db2060c80471d6d97a173407c41fa4ca58396f6f879826e4f78b7f58282c8e48c664c9f8c953ab2e7a727125030fbf02ffa94172ae1a5c5b1be1b8bddb20ea698d49150aa361ed56504daa3c8f6f7bc1e58f024dff40892db134da0b61e58fa82317afa6884ae14f5d739b5e95fc1b56d645b75d60302775aac94d1bf52a103eefbad9cecd61fbbad37c9dbccceeb9007861ee3f34e4a546b7fe6b5b195ef1fee6ba8080d5d228bd721904b0d5010dab6e4eca9b82653721946aac8401200000000000000000000000000000000000000000000000000000000000000001a5fb3bfe499a0fa285e7129a88962e278fc65e821851d4234ada909ac72a77e5";

    let usk0 =
        x"8244fcbe49870a4d4aa947b7034a873e168580e18b5834ea34940dc9f492eda03a9b20c3c3c120b1a462f1642575e0cc";
    let usk1 =
        x"a0f04b759ed2ff477f0fe5b672992235205d2af502f659d4bbb484b745e35fd7a9ff11e37e12111023a891c3fa98a2d3";

    let user_secret_keys = vector[g1_from_bytes(&usk0), g1_from_bytes(&usk1)];
    let pks = vector[get_public_key(&s0), get_public_key(&s1)];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        @0x0,
        x"381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409",
        &pks,
    );
    let all_pks = vector[get_public_key(&s0), get_public_key(&s1), get_public_key(&s2)];

    let encrypted_object = parse_encrypted_object(encrypted_object);
    let decrypted = decrypt(&encrypted_object, &vdks, &all_pks);
    assert!(decrypted.borrow() == b"Hello, world!");

    test_scenario::return_shared(s0);
    test_scenario::return_shared(s1);
    test_scenario::return_shared(s2);

    destroy_cap(cap0);
    destroy_cap(cap1);
    destroy_cap(cap2);
    test_scenario::end(scenario);
}
