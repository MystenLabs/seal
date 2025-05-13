// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::errors::InternalError;
use crate::return_err;
use crate::KeyId;
use crypto::create_full_id;
use fastcrypto::encoding::{Base64, Encoding};
use sui_sdk::types::transaction::{Argument, CallArg, Command, ProgrammableTransaction};
use sui_types::base_types::ObjectID;
use sui_types::transaction::ProgrammableMoveCall;
use tracing::debug;

///
/// PTB that is valid for evaluating a policy. See restrictions in try_from below.
///
pub struct ValidPtb(ProgrammableTransaction);

impl TryFrom<ProgrammableTransaction> for ValidPtb {
    type Error = InternalError;

    fn try_from(ptb: ProgrammableTransaction) -> Result<Self, Self::Error> {
        debug!("Creating vptb from: {:?}", ptb);

        // Restriction: The PTB must have at least one input and one command.
        if ptb.inputs.is_empty() || ptb.commands.is_empty() {
            return_err!(
                InternalError::InvalidPTB("Empty PTB input or command".to_string()),
                "Invalid PTB {:?}",
                ptb
            );
        }

        // Checked above that there is at least one command
        let Command::MoveCall(first_cmd) = &ptb.commands[0] else {
            return_err!(
                InternalError::InvalidPTB("Invalid first command".to_string()),
                "Invalid PTB first command {:?}",
                ptb
            );
        };
        let pkg_id = first_cmd.package;

        for cmd in &ptb.commands {
            // Restriction: All commands must be a MoveCall.
            let Command::MoveCall(cmd) = &cmd else {
                return_err!(
                    InternalError::InvalidPTB("Non MoveCall command".to_string()),
                    "Non MoveCall command {:?}",
                    cmd
                );
            };

            // Restriction: The first argument to the move call must be a non-empty id.
            let _ = get_key_id(&ptb, cmd)?;

            // Restriction: The called function must start with the prefix seal_approve.
            // Restriction: All commands must use the same package id.
            if !cmd.function.starts_with("seal_approve") || cmd.package != pkg_id {
                return_err!(
                    InternalError::InvalidPTB("Invalid function or package id".to_string()),
                    "Invalid function or package id {:?}",
                    cmd
                );
            }
        }

        // TODO: sanity checks - non mutable objs.

        Ok(ValidPtb(ptb))
    }
}

fn get_key_id(
    ptb: &ProgrammableTransaction,
    cmd: &ProgrammableMoveCall,
) -> Result<KeyId, InternalError> {
    if cmd.arguments.is_empty() {
        return_err!(
            InternalError::InvalidPTB("Empty args".to_string()),
            "Invalid PTB command {:?}",
            cmd
        );
    }
    let Argument::Input(arg_idx) = cmd.arguments[0] else {
        return_err!(
            InternalError::InvalidPTB("Invalid index for first argument".to_string()),
            "Invalid PTB command {:?}",
            cmd
        );
    };
    let CallArg::Pure(id) = &ptb.inputs[arg_idx as usize] else {
        return_err!(
            InternalError::InvalidPTB("Invalid first parameter for seal_approve".to_string()),
            "Invalid PTB command {:?}",
            cmd
        );
    };
    bcs::from_bytes(id).map_err(|_| {
        InternalError::InvalidPTB("Invalid BCS for first parameter for seal_approve".to_string())
    })
}

impl ValidPtb {
    pub fn try_from_base64(s: &str) -> Result<Self, InternalError> {
        Base64::decode(s)
            .map_err(|_| InternalError::InvalidPTB("Invalid Base64".to_string()))
            .and_then(|b| {
                bcs::from_bytes::<ProgrammableTransaction>(&b)
                    .map_err(|_| InternalError::InvalidPTB("Invalid BCS".to_string()))
            })
            .and_then(ValidPtb::try_from)
    }

    // The ids without the pkgId prefix
    pub fn inner_ids(&self) -> Vec<KeyId> {
        self.0
            .commands
            .iter()
            .map(|cmd| {
                let Command::MoveCall(cmd) = cmd else {
                    unreachable!()
                };
                get_key_id(&self.0, cmd).expect("checked above")
            })
            .collect()
    }

    pub fn pkg_id(&self) -> ObjectID {
        let Command::MoveCall(cmd) = &self.0.commands[0] else {
            unreachable!()
        };
        cmd.package
    }

    pub fn full_ids(&self, first_pkg_id: &ObjectID) -> Vec<KeyId> {
        self.inner_ids()
            .iter()
            .map(|inner_id| create_full_id(&first_pkg_id.into_bytes(), inner_id))
            .collect()
    }

    pub fn ptb(&self) -> &ProgrammableTransaction {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_sdk::types::base_types::SuiAddress;
    use sui_types::base_types::ObjectID;
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::Identifier;

    #[test]
    fn test_valid() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve_x").unwrap(),
            vec![],
            vec![id_caller],
        );
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla2").unwrap(),
            Identifier::new("seal_approve_y").unwrap(),
            vec![],
            vec![id_caller],
        );
        let ptb = builder.finish();
        let valid_ptb = ValidPtb::try_from(ptb).unwrap();

        assert_eq!(valid_ptb.inner_ids(), vec![id.clone(), id]);
        assert_eq!(valid_ptb.pkg_id(), pkgid);
    }

    #[test]
    fn test_invalid_empty_ptb() {
        let builder = ProgrammableTransactionBuilder::new();
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Empty PTB input or command".to_string()
            ))
        );
    }

    #[test]
    fn test_invalid_no_inputs() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve").unwrap(),
            vec![],
            vec![],
        );
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Empty PTB input or command".to_string()
            ))
        );
    }

    #[test]
    fn test_invalid_non_move_call() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let sender = SuiAddress::random_for_testing_only();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();

        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve_x").unwrap(),
            vec![],
            vec![id_caller],
        );
        // Add a transfer command instead of move call
        builder.transfer_sui(sender, Some(1));
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Non MoveCall command".to_string()
            ))
        );
    }

    #[test]
    fn test_invalid_different_package_ids() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let id = builder.pure(vec![1u8, 2, 3]).unwrap();
        let pkgid1 = ObjectID::random();
        let pkgid2 = ObjectID::random();
        builder.programmable_move_call(
            pkgid1,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve").unwrap(),
            vec![],
            vec![id],
        );
        builder.programmable_move_call(
            pkgid2, // Different package ID
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve").unwrap(),
            vec![],
            vec![id],
        );
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Invalid function or package id".to_string()
            ))
        );
    }
}
