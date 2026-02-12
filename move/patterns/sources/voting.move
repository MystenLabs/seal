// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Voting pattern:
/// - Anyone can create a vote with a set of voters.
/// - The voters can submit their encrypted votes.
/// - After all the voters have submitted votes, anyone can retrieve the encryption keys and submit them. The votes are then decrypted on-chain.
/// - Invalid votes are ignored.
///
/// This is an example of on-chain decryption. Other use cases of this include auctions, timelocked voting, etc.
///
/// This pattern does NOT implement versioning, please see other patterns for examples of versioning.
///
module patterns::voting;

use seal::bf_hmac_encryption::{
    EncryptedObject,
    VerifiedDerivedKey,
    PublicKey,
    decrypt,
    new_public_key,
    verify_derived_keys,
    parse_encrypted_object
};
use sui::bls12381::g1_from_bytes;

const EInvalidVote: u64 = 1;
const EVoteNotDone: u64 = 2;
const EAlreadyFinalized: u64 = 3;
const ENotEnoughKeys: u64 = 4;

/// This represents a vote.
public struct Vote has key {
    /// The id of a vote is the id of the object.
    id: UID,
    /// The eligble voters of the vote.
    voters: vector<address>,
    /// The number of options the voters can vote for.
    options: u8,
    /// This holds the encrypted votes assuming the same order as the `voters` vector.
    votes: vector<Option<EncryptedObject>>,
    /// Is the vote finalixed yet
    is_finalized: bool,
    /// The key servers that must be used for the encryption of the votes.
    key_servers: vector<address>,
    /// The public keys for the key servers in the same order as `key_servers`.
    public_keys: vector<vector<u8>>,
    /// The threshold for the vote.
    threshold: u8,
}

// The id of a vote is the id of the object.
public fun id(v: &Vote): vector<u8> {
    object::id(v).to_bytes()
}

/// The result of a vote.
public struct VoteResult has drop, store {
    vote_id: address,
    result: vector<u64>,
}

public fun votes_for_option(result: &VoteResult, option: u8): u64 {
    result.result[option as u64]
}

public fun vote_id(result: &VoteResult): address {
    result.vote_id
}

public fun winner(result: &VoteResult): u8 {
    let (mut max_votes, mut option) = (0u64, 0u8);
    result.result.length().do!(|i| {
        let votes = result.result[i];
        if (votes > max_votes) {
            max_votes = votes;
            option = i as u8;
        };
    });
    option
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
    options: u8,
    key_servers: vector<address>,
    public_keys: vector<vector<u8>>,
    threshold: u8,
    ctx: &mut TxContext,
): Vote {
    assert!(threshold <= key_servers.length() as u8);
    assert!(key_servers.length() == public_keys.length());
    Vote {
        id: object::new(ctx),
        voters,
        key_servers,
        public_keys,
        threshold,
        is_finalized: false,
        votes: vector::tabulate!(voters.length(), |_| option::none()),
        options,
    }
}

/// Cast a vote.
/// The encrypted object should be an encryption of a single u8 and have the senders address as aad.
public fun cast_vote(vote: &mut Vote, encrypted_vote: vector<u8>, ctx: &mut TxContext) {
    let encrypted_vote = parse_encrypted_object(encrypted_vote);

    // The voter id must be put as aad to ensure that an encrypted vote cannot be copied and cast by another voter.
    assert!(encrypted_vote.aad().borrow() == ctx.sender().to_bytes(), EInvalidVote);

    // All encrypted vote must have been encrypted using the same key servers and the same threshold.
    // We could allow the order of the key servers to be different, but for the sake of simplicity, we also require the same order.
    assert!(encrypted_vote.services() == vote.key_servers, EInvalidVote);
    assert!(encrypted_vote.threshold() == vote.threshold, EInvalidVote);

    // Check that the encryptions were created for this vote.
    assert!(encrypted_vote.id() == vote.id(), EInvalidVote);
    assert!(encrypted_vote.package_id() == @0x0, EInvalidVote);

    // This aborts if the sender is not a voter.
    let index = vote.voters.find_index!(|voter| voter == ctx.sender()).destroy_some();
    vote.votes[index].fill(encrypted_vote);
}

entry fun seal_approve(id: vector<u8>, vote: &Vote) {
    assert!(id == vote.id(), EInvalidVote);
    assert!(vote.votes.all!(|vote| vote.is_some()), EVoteNotDone);
}

/// Finalize a vote.
/// Updates the `result` field of the vote to hold the votes of the corresponding voters.
/// Aborts if the vote has already been finalized.
/// Aborts if there are not enough keys or if they are not valid, e.g. if they were derived for a different purpose.
/// In case the keys are valid but a vote, is invalid, decrypt will just set the corresponding result to none.
///
/// The given derived keys and key servers should be in the same order.
public fun finalize_vote(
    vote: &mut Vote,
    derived_keys: &vector<vector<u8>>,
    key_servers: &vector<address>,
): VoteResult {
    assert!(!vote.is_finalized, EAlreadyFinalized);
    assert!(key_servers.length() == derived_keys.length());
    assert!(derived_keys.length() as u8 >= vote.threshold, ENotEnoughKeys);

    // Public keys for the given derived keys
    // Verify the derived keys
    let verified_derived_keys: vector<VerifiedDerivedKey> = verify_derived_keys(
        &derived_keys.map_ref!(|k| g1_from_bytes(k)),
        @0x0,
        vote.id(),
        &key_servers
            .map_ref!(|ks1| vote.key_servers.find_index!(|ks2| ks1 == ks2).destroy_some())
            .map!(|i| new_public_key(vote.key_servers[i].to_id(), vote.public_keys[i])),
    );

    // Public keys for all key servers
    let all_public_keys: vector<PublicKey> = vote
        .key_servers
        .zip_map!(vote.public_keys, |ks, pk| new_public_key(ks.to_id(), pk));

    // This aborts if there are not enough keys or if they are invalid, e.g. if they were derived for a different purpose.
    // However, in case the keys are valid but some of the encrypted objects, aka the votes, are invalid, decrypt will just return none for these votes.
    let mut result = vector::tabulate!(vote.options as u64, |_| 0);
    vote
        .votes
        .do_ref!(
            |v| v
                .and_ref!(|v| decrypt(v, &verified_derived_keys, &all_public_keys))
                .do_ref!(|decrypted| {
                    if (decrypted.length() == 1 && decrypted[0] < vote.options) {
                        let option = decrypted[0] as u64;
                        *&mut result[option] = result[option] + 1;
                    };
                }),
        );

    vote.is_finalized = true;
    VoteResult { vote_id: vote.id.to_address(), result }
}

#[test]
fun test_vote() {
    use seal::key_server::{create_and_transfer_v1, KeyServer, destroy_for_testing as ks_destroy};
    use sui::test_scenario::{Self, next_tx, ctx};

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    // Setup key servers.
    let pk0 =
        x"a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161";
    create_and_transfer_v1(
        b"mysten0".to_string(),
        b"https://mysten-labs.com".to_string(),
        0,
        pk0,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);
    let s0: KeyServer = scenario.take_from_sender();

    let pk1 =
        x"a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6";
    create_and_transfer_v1(
        b"mysten1".to_string(),
        b"https://mysten-labs.com".to_string(),
        0,
        pk1,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);
    let s1: KeyServer = scenario.take_from_sender();

    let pk2 =
        x"93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651";
    create_and_transfer_v1(
        b"mysten2".to_string(),
        b"https://mysten-labs.com".to_string(),
        0,
        pk2,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);
    let s2: KeyServer = scenario.take_from_sender();

    // Anyone can create a vote.
    let mut vote = create_vote(
        vector[@0x1, @0x2, @0x3, @0x4], // voters
        3,
        vector[s0.id(), s1.id(), s2.id()],
        vector[pk0, pk1, pk2],
        2,
        scenario.ctx(),
    );

    let id = x"75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05";

    // Vote on 1
    // cargo run --bin seal-cli encrypt-hmac --message 0x01 --aad 0x0000000000000000000000000000000000000000000000000000000000000001 --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    scenario.next_tx(@0x1);
    let encrypted_vote_1 =
        x"0000000000000000000000000000000000000000000000000000000000000000002075c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e0503034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97030200a5f116cadc50530e4b2987a3ac183f121650367e0021e357d960de848c6c61de7331e2e65534ebf94508c006464bdd8406690c5034b8ae7dea889e17f32e340767ff940fa7c1e01c0b43214be17cf5020a87e3a72a99f6bab70c6c08b269a04803463655be2ed5e10556188e085081b1a0415e002b52be9386d66dfa175308173faca55f4e7aeab0559b973aec811a169bba82e873a3c2e176e9d3161d1848e55382a289975348f2aa52edcd1f908baf66bfd75e54826a50333df65c4ecb3088ec7bed6b11ca4c03586ad6a2cadb1e379d33d2a65212e5457a65c3b69ad8e66ba00101b8012000000000000000000000000000000000000000000000000000000000000000019282326a203b08b24b508107f23ed98c306ee73cc04f228a66bdefd5e9f44cb6";
    cast_vote(&mut vote, encrypted_vote_1, scenario.ctx());

    // Vote on 2
    // cargo run --bin seal-cli encrypt-hmac --message 0x02 --aad 0x0000000000000000000000000000000000000000000000000000000000000002 --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    scenario.next_tx(@0x2);
    let encrypted_vote_2 =
        x"0000000000000000000000000000000000000000000000000000000000000000002075c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e0503034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a9703020094febd743a9da981328deba26dd19f39d145bae4e131e9839db2101b76ea04342b302d95b4bf8ff9f5530376ee73206800d0902e622c7b7adb32a9fe4530fd27a12d40dfaaf89e71f513f44cd30dc133c8a9a4bc6df5b51a0f3dc0a393cea8e2032d4e5e1b74730b57af98e254b7a747a6be31370151d020681c545966377937969a3db369ac061c3432cdc84f0e83091277de81c0c3d79ed90a96d3dc37ab074cef24780ee29bc2a23c1af069fd4d0bb364209937f7de7890a0ddeca441f61afc546378d006a4e72d65515c2d4f5aff1a6e4262f72200159ce7c62c11588cae8f0101d1012000000000000000000000000000000000000000000000000000000000000000024832a280c8ceba7aba3311045889f0ffb8911172ef9f0481174863509afeaf23";
    cast_vote(&mut vote, encrypted_vote_2, scenario.ctx());

    // Vote on 1
    // cargo run --bin seal-cli encrypt-hmac --message 0x01 --aad 0x0000000000000000000000000000000000000000000000000000000000000003 --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    scenario.next_tx(@0x3);
    let encrypted_vote_3 =
        x"0000000000000000000000000000000000000000000000000000000000000000002075c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e0503034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a9703020080038b7834acc32d0a064a2848bec777ed3b6de0d3dc32681a7d78ca41a9430e5c360d9584622ca6a99b5dc3df55ce461993460772ef12e71a10baabc48b5bbfd12f040929042dcd267a4c1a448a4fd3fa64d5223bc1f18ea199ad1a4656095e031dcc34cd14d33ff6ccf0c1c55de6f303abf6b31021b6fb1a5e1fd86fd1f0225cbc790834b9110bdd4041198f5f6047a3f387291e5213310569a18650eceae6020575cafc8f116500e23ff74584e13492087ec3acb6694a443976803432944a3bea6eadd13d7216d7455064a766a320cc927987b009c1cdd7edbb653e274d45920101f40120000000000000000000000000000000000000000000000000000000000000000376469d0b90754f2ca787d4069f23177d6befb4db8ae2a72ae1cea3a7966e9315";
    cast_vote(&mut vote, encrypted_vote_3, scenario.ctx());

    // Invalid vote -- used a wrong public key for the last key server. Wil be ignored in the tally.
    // cargo run --bin seal-cli encrypt-hmac --message 0x01 --aad 0x0000000000000000000000000000000000000000000000000000000000000004 --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    scenario.next_tx(@0x4);
    let encrypted_vote_4 =
        x"0000000000000000000000000000000000000000000000000000000000000000002075c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e0503034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97030200a00c7636602615d1dcd59fd8646fcd1771579fe7a08eb6b14a8318f9df3abebcc5f373c93276ab7641537bee61eeb4fe0dd508e83158ff47f4d38d253093bf3e9d4a0fe615a8445439feed4d47fb03a7dce8bb6108ae1e7d2099687257a859a703772b01b72374e3cd2d4b7d55a6b7d3e3af9d61c6fe1c5945e4493b0aca8dc92ae11d736c1eebeb5e23694082d840aef0370c4d39bf8e9f6399198f9a44746e718f2ed8f10e55ae719ba362ca9ded236f6d7628fb9436722511a492b1d4b24de0c7e5aece4be65d1e879a573023e9f98a96353c144369da2cf7939af0c7c13e2301015f0120000000000000000000000000000000000000000000000000000000000000000460c28936339b4aa39a7cf8d69033b6d5137d223cb3215c972f2052cf7a17ac78";
    cast_vote(&mut vote, encrypted_vote_4, scenario.ctx());

    // The derived keys. These should have been retrieved from key servers. They can also be computed from the cli:
    // cargo run --bin seal-cli extract --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --master-key 3c185eb32f1ab43a013c7d84659ec7b59791ca76764af4ee8d387bf05621f0c7
    let dk0 =
        x"a24161c1c8398aac9942aed38e9ad9c923f033f75f067f8a3a511f313d03e2b722671a01f20d9d56ae30913994190a5b";
    // cargo run --bin seal-cli extract --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --master-key 09ba20939b2300c5ffa42e71809d3dc405b1e68259704b3cb8e04c36b0033e24
    let dk1 =
        x"b1ecf1d8da591deac2cf271048a327cb731809e0187ae8bcd54c79e92bf58c7b96e415eb1dbe62b6ced54de3197b249b";

    // Finalize vote
    let result = finalize_vote(
        &mut vote,
        &vector[dk0, dk1],
        &vector[s0.id(), s1.id()],
    );

    assert!(result.vote_id().to_bytes() == id);
    assert!(result.votes_for_option(0) == 0);
    assert!(result.votes_for_option(1) == 2);
    assert!(result.votes_for_option(2) == 1);
    assert!(result.winner() == 1);

    // Clean up
    ks_destroy(s0);
    ks_destroy(s1);
    ks_destroy(s2);
    destroy_for_testing(vote);
    scenario.end();
}
