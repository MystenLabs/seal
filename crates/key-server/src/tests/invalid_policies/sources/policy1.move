// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module test::policy1;

// Invalid first parameter, should be vector<u8>
entry fun seal_approve(id: u64) {
    ()
}
