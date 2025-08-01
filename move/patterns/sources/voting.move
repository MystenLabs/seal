// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Voting pattern:
/// - Anyone can create a vote with a set of voters.
/// - The voters can submit their encrypted votes.
/// - After all the voters have submitted votes, anyone can retrieve the encryption keys and submit them. The votes are then decrypted on-chain.
///
/// This is an example of on-chain decryption. Other use cases of this include auctions, timelocked voting, etc.
///
/// This pattern does NOT implement versioning, please see other patterns for 
/// examples of versioning.
///
module patterns::voting;

use seal::bf_hmac_encryption::{EncryptedObject, VerifiedDerivedKey, PublicKey, decrypt};

const EInvalidVote: u64 = 1;
const EVoteNotDone: u64 = 2;
const EAlreadyFinalized: u64 = 3;

/// This represents a vote.
public struct Vote has key {
    /// The id of a vote is the id of the object.
    id: UID,
    /// The eligble voters of the vote.
    voters: vector<address>,
    /// This holds the encrypted votes assuming the same order as the `voters` vector.
    votes: vector<Option<EncryptedObject>>,
    /// This will be set after the vote is finalised. The vote options are represented by a Option<u8> which is None if the vote was invalid.
    result: Option<vector<Option<u8>>>,
    /// The key servers that must be used for the encryption of the votes.
    key_servers: vector<ID>,
    /// The threshold for the vote.
    threshold: u8,
}

// The id of a vote is the id of the object.
public fun id(v: &Vote): vector<u8> {
    object::id(v).to_bytes()
}

#[test_only]
public fun destroy_for_testing(v: Vote) {
    let Vote { id, .. } = v;
    object::delete(id);
}

/// Create a vote.
/// The associated key-ids are [pkg id][vote id].
public fun create_vote(
    voters: vector<address>,
    key_servers: vector<ID>,
    threshold: u8,
    ctx: &mut TxContext,
): Vote {
    assert!(threshold <= key_servers.length() as u8);
    Vote {
        id: object::new(ctx),
        voters,
        key_servers,
        threshold,
        votes: vector::tabulate!(voters.length(), |_| option::none()),
        result: option::none(),
    }
}

/// Cast a vote.
/// The encrypted object should be an encryption of a single u8 and have the senders address as aad.
public fun cast_vote(vote: &mut Vote, encrypted_vote: EncryptedObject, ctx: &mut TxContext) {
    // The voter id must be put as aad to ensure that an encrypted vote cannot be copied and cast by another voter.
    assert!(encrypted_vote.aad().borrow() == ctx.sender().to_bytes(), EInvalidVote);

    // All encrypted vote must have been encrypted using the same key servers and the same threshold.
    // We could allow the order of the key servers to be different, but for the sake of simplicity, we also require the same order.
    assert!(encrypted_vote.services() == vote.key_servers.map_ref!(|id| id.to_address()));
    assert!(encrypted_vote.threshold() == vote.threshold);

    // This aborts if the sender is not a voter.
    let index = vote.voters.find_index!(|voter| voter == ctx.sender()).extract();
    vote.votes[index].fill(encrypted_vote);
}

entry fun seal_approve(id: vector<u8>, vote: &Vote) {
    assert!(id == object::id(vote).to_bytes(), EInvalidVote);
    assert!(vote.votes.all!(|vote| vote.is_some()), EVoteNotDone);
}

/// Finalize a vote.
/// Updates the `result` field of the vote to hold the votes of the corresponding voters.
/// Aborts if the vote has already been finalized.
/// Aborts if there are not enough keys or if they are not valid, e.g. if they were derived for a different purpose.
/// In case the keys are valid but a vote, is invalid, decrypt will just set the corresponding result to none.
public fun finalize_vote(
    vote: &mut Vote,
    keys: &vector<VerifiedDerivedKey>,
    public_keys: &vector<PublicKey>,
) {
    assert!(vote.result.is_none(), EAlreadyFinalized);

    // This aborts if there are not enough keys or if they are invalid, e.g. if they were derived for a different purpose.
    // However, in case the keys are valid but some of the encrypted objects, aka the votes, are invalid, decrypt will just return none for these votes.
    vote.result.fill(vote.votes.map_ref!(|vote| {
        let decrypted = decrypt(vote.borrow(), keys, public_keys);
        if (decrypted.is_some()) {
            let v = decrypted.borrow();
            // We expect the vote to be a single byte.
            if (v.length() == 1) {
                return option::some(v[0])
            }
        };
        option::none()
    }));
    // The encrypted votes can be deleted here if they are not needed anymore.
}

#[test]
fun test_vote() {
    use seal::bf_hmac_encryption::{verify_derived_keys, get_public_key};
    use seal::key_server::{create_v1, KeyServer, destroy_for_testing as ks_destroy};
    use std::string;
    use seal::bf_hmac_encryption::parse_encrypted_object;
    use sui::test_scenario::{Self, next_tx, ctx};
    use sui::bls12381::g1_from_bytes;

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    // Setup key servers.
    let pk0 =
        x"a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161";
    create_v1(
        string::utf8(b"mysten0"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk0,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s0: KeyServer = scenario.take_from_sender();

    let pk1 =
        x"a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6";
    create_v1(
        string::utf8(b"mysten1"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk1,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s1: KeyServer = scenario.take_from_sender();

    let pk2 =
        x"93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651";
    create_v1(
        string::utf8(b"mysten2"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk2,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s2: KeyServer = scenario.take_from_sender();

    // Anyone can create a vote.
    let mut vote = create_vote(
        vector[@0x1, @0x2],
        vector[s0.id().to_inner(), s1.id().to_inner(), s2.id().to_inner()],
        2,
        scenario.ctx(),
    );

    // cargo run --bin seal-cli encrypt-hmac --message 0x07 --aad 0x0000000000000000000000000000000000000000000000000000000000000001 --package-id 0x0 --id 0x381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    // cargo run --bin seal-cli encrypt-hmac --message 0x2a --aad 0x0000000000000000000000000000000000000000000000000000000000000002 --package-id 0x0 --id 0x381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --threshold 2 a6b8194ba6ffa1bf4c4e13ab1e56833f99f45f97874e77b845b361305ddaa741174febc307d3e07f7d4d5bb08c0adf3d11a5b8774c84006fb0ba7435f045f56a61905bc283049c2175984528e40a36e0096aabd401a67b1ccc442416c33b5df9 ac1c15fe6c5476ebc8b5bc432dcea06a30c87f89d21b89159ceab06afb84e0e7edefaadb896771ee281d25b6845aa3a20bda9324de39a9909c00f09b344b053da835dfde943c995576ec5e2fcf93221006bb2fcec8ef5096b4b88c36e1aa861c a8750277f240eb4d94c159b2ec47c1c19396f6e33691fbf50514906b3e70c0454d9a79cf1f1f5562e4ddad9c4505bfb405a9901ac6ba2a51c24919d7599c74a5155f83606f80c1a302de9865deb4577911493dc1608754d67051f755cd44c391 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97

    // Cast votes. These have been encrypted using the Seal CLI.
    scenario.next_tx(@0x1);
    let encrypted_vote_1 = parse_encrypted_object(
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a970302008f1467ece08182e4e2fd8db89fd35ad91d941e77032e4cb0b09ffc34a18d5b124424bbab1e0d04598aaf551249b49e69114fa61470c48358a3168bf2d64822208809608de09b5ba98464eec0145f7d5ce33ba11792c23d9800569b9bee50c20003e2a81dcf1d9cd1d956f9c28657bf72d5d73cd38628a4f6141b5440df84b3e857159d9a5e18ac2d6b50093e09598c51a672b15f04db4b19a4a65b88f1cb479c46d13cbf1b5a89a2578c6e5aa8e49c55e92e9d6a230ebfcda29bbd2c6bf4cd6378d6fda1f4cc560ae45c99528d54c24a3f4e35e721de0196c55976f9f7d91488350101f201200000000000000000000000000000000000000000000000000000000000000001800bbeb31dc75e23f2d0c3571a2a53689bb5d4c74393325e9ced0069f5e3d318",
    );
    cast_vote(&mut vote, encrypted_vote_1, scenario.ctx());

    scenario.next_tx(@0x2);
    let encrypted_vote_2 = parse_encrypted_object(
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97030200960456031a4160ea083e46f653fe268170717eb95dd230ae59aa2630444673260ef5593a80826fcd9cb9e9ab3ae95a6a03b6340c6aaba2560d4276b1ab4b7be0cb8bf902c62dbef7f93487b0f9ba82bdc70a4ea34f2bc1361d61158f350b31de036e76d2e00088e53081ec6f3dfb746780923409fd38f22115ee002e499087fc41d04c66d0874cb8970c3063bcd9b15a2a975946b795854409b013eae56f63df4d2dd992d0fe58c17d1e7b4586a197466046f335ffdfb8fcefc6489dbc90b6d81db3178753c8313fc43d1d2679d2e256c18c54df1a28d0cfbae73ae4b31a249e5f010101012000000000000000000000000000000000000000000000000000000000000000025e181e20f8740650c4347d41a3b69ac67aae69f74ab3fa575d60efef1a46de06",
    );
    cast_vote(&mut vote, encrypted_vote_2, scenario.ctx());

    // Both voters have now voted, so the vote is sealed and seal_approve will succeed.
    seal_approve(vote.id(), &vote);

    // The derived keys. These should have been retrieved from key servers
    let dk0 = g1_from_bytes(
        &x"8cb19351dbd351d02292a77a18e2f0f4ec0d3becf23f37cc87e4870bf35522c3e59487e0ee5023d5e2e383e40b77bd98",
    );
    let dk1 = g1_from_bytes(
        &x"a7f6b22719b8ca2e3bfc07bf22ea59245b4aec7a394020cf826199b3cc71e58045e5d6b52506145851e71370e524c362",
    );

    // Verify the derived keys
    let user_secret_keys = vector[dk0, dk1];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        @0x0,
        x"381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409",
        &vector[get_public_key(&s0), get_public_key(&s1)],
    );

    // Finalize vote
    assert!(vote.result.is_none());
    finalize_vote(
        &mut vote,
        &vdks,
        &vector[get_public_key(&s0), get_public_key(&s1), get_public_key(&s2)],
    );
    assert!(vote.result.is_some());

    // Voter 1 voted '7' and voter 2 voted '42'.
    assert!(vote.result.borrow()[0].borrow() == 7);
    assert!(vote.result.borrow()[1].borrow() == 42);

    // Clean up
    ks_destroy(s0);
    ks_destroy(s1);
    ks_destroy(s2);
    destroy_for_testing(vote);
    test_scenario::end(scenario);
}
