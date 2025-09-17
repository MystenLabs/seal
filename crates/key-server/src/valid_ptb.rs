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

// Should only increase this with time.
const MAX_COMMANDS: usize = 100;

// Size limits to prevent DoS attacks
const MAX_BASE64_LENGTH: usize = 1024 * 1024; // 1MB
const MAX_DECODED_SIZE: usize = 512 * 1024;   // 512KB

impl TryFrom<ProgrammableTransaction> for ValidPtb {
    type Error = InternalError;

    fn try_from(ptb: ProgrammableTransaction) -> Result<Self, Self::Error> {
        debug!("Creating vptb from: {:?}", ptb);

        if ptb.commands.len() > MAX_COMMANDS {
            return_err!(
                InternalError::InvalidPTB(format!(
                    "Too many commands in PTB (more than {})",
                    MAX_COMMANDS
                )),
                "Too many commands in PTB: {:?}",
                ptb
            );
        }

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
        // Prevent DoS attacks by limiting input size
        if s.len() > MAX_BASE64_LENGTH {
            return Err(InternalError::InvalidPTB(format!(
                "Input too large (max {} bytes)",
                MAX_BASE64_LENGTH
            )));
        }

        let decoded = Base64::decode(s)
            .map_err(|_| InternalError::InvalidPTB("Invalid Base64".to_string()))?;

        // Prevent DoS attacks by limiting decoded size
        if decoded.len() > MAX_DECODED_SIZE {
            return Err(InternalError::InvalidPTB(format!(
                "Decoded data too large (max {} bytes)",
                MAX_DECODED_SIZE
            )));
        }

        bcs::from_bytes::<ProgrammableTransaction>(&decoded)
            .map_err(|_| InternalError::InvalidPTB("Invalid BCS".to_string()))
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

    #[test]
    fn test_dos_protection_large_base64_input() {
        // Test that overly large Base64 inputs are rejected
        let large_input = "A".repeat(MAX_BASE64_LENGTH + 1);
        let result = ValidPtb::try_from_base64(&large_input);
        assert!(result.is_err());
        
        match result.err().unwrap() {
            InternalError::InvalidPTB(msg) => {
                assert!(msg.contains("Input too large"));
            }
            _ => panic!("Expected InvalidPTB error"),
        }
    }

    #[test]
    fn test_dos_protection_large_decoded_data() {
        // Create a valid PTB and then encode it with padding to exceed size limit
        let mut builder = ProgrammableTransactionBuilder::new();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve_test").unwrap(),
            vec![],
            vec![id_caller],
        );
        let ptb = builder.finish();
        let valid_ptb = ValidPtb::try_from(ptb).unwrap();
        
        // Serialize the PTB
        let ptb_bytes = bcs::to_bytes(valid_ptb.ptb());
        
        // Create malicious input: valid PTB + extra padding to exceed size limit
        let mut malicious_bytes = ptb_bytes;
        malicious_bytes.extend(vec![0u8; MAX_DECODED_SIZE + 1]);
        
        // Encode as Base64
        let malicious_base64 = Base64::encode(&malicious_bytes);
        
        // This should fail due to size limit
        let result = ValidPtb::try_from_base64(&malicious_base64);
        assert!(result.is_err());
        
        match result.err().unwrap() {
            InternalError::InvalidPTB(msg) => {
                assert!(msg.contains("Decoded data too large"));
            }
            _ => panic!("Expected InvalidPTB error"),
        }
    }

    #[test]
    fn test_dos_protection_valid_size_limits() {
        // Test that inputs within size limits are accepted
        let mut builder = ProgrammableTransactionBuilder::new();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve_test").unwrap(),
            vec![],
            vec![id_caller],
        );
        let ptb = builder.finish();
        let valid_ptb = ValidPtb::try_from(ptb).unwrap();
        
        // Serialize and encode - should be well within limits
        let ptb_bytes = bcs::to_bytes(valid_ptb.ptb());
        let base64_input = Base64::encode(&ptb_bytes);
        
        // This should succeed
        let result = ValidPtb::try_from_base64(&base64_input);
        assert!(result.is_ok());
    }
}
