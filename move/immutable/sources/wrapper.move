// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// This module implements a capability-based access control pattern for shared objects.
/// The idea is that a shared object Wrapper<T> contains an immutable T object,
/// but access to it is controlled by whoever holds the corresponding Cap.
/// 
/// Usage pattern:
/// - Each committee member has a Cap to Wrapper<Committee>
/// - The Committee has a Cap to Wrapper<KeyServer>
/// 
/// This makes the ownership of T upgradable (by transferring the Cap),
/// while the shared T object itself remains immutable.
module immutable::wrapper;

const EInvalidCap: u64 = 1;

/// Capability object that grants access to a specific Wrapper<T>
public struct Cap has key, store {
    id: UID,
    obj_id: ID
}

/// Wrapper that holds an object T and can only be accessed with the matching Cap
public struct Wrapper<T: store> has key {
    id: UID,
    obj: T,
}

/// Create a new wrapped object and return its capability
public fun wrap<T: store>(obj: T, ctx: &mut TxContext): (Wrapper<T>, Cap) {
    let wrapper = Wrapper {
        id: object::new(ctx),
        obj,
    };
    let wrapper_id = object::id(&wrapper);
    let cap = Cap {
        id: object::new(ctx),
        obj_id: wrapper_id
    };
    (wrapper, cap)
}

/// Get a reference to the wrapped object using the capability
public fun get<T: store>(wrapper: &Wrapper<T>, cap: &Cap): &T {
    assert!(cap.obj_id == object::id(wrapper), EInvalidCap);
    &wrapper.obj
}

/// Get a mutable reference to the wrapped object using the capability
public fun get_mut<T: store>(wrapper: &mut Wrapper<T>, cap: &Cap): &mut T {
    assert!(cap.obj_id == object::id(wrapper), EInvalidCap);
    &mut wrapper.obj
}

/// Transfer the capability to a new owner
public fun transfer_cap(cap: Cap, recipient: address) {
    transfer::transfer(cap, recipient);
}

/// Share the wrapper object (typically done right after creation)
public fun share_wrapper<T: store>(wrapper: Wrapper<T>) {
    transfer::share_object(wrapper);
}