// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::time::current_epoch_time;
use move_core_types::identifier::Identifier;
use std::str::FromStr;
use sui_rpc::proto::sui::rpc::v2::execution_error::ErrorDetails;
use sui_rpc::proto::sui::rpc::v2::SimulateTransactionResponse;
use sui_types::base_types::ObjectID;
use sui_types::transaction::Argument::Input;
use sui_types::transaction::{Argument, CallArg, Command, ObjectArg, ProgrammableTransaction};
use sui_types::SUI_CLOCK_OBJECT_ID;

const TESTNET_PACKAGE_ID: &str =
    "0xdccbeb87767be2b2346af5575eb139807205e4c23ec53dc616f951fe1d814112";
const MAINNET_PACKAGE_ID: &str =
    "0x931739224160073d8e391c9aa6e7ade9818e9814b4907066b7efa058636c4e45";

/// These should be equal to the corresponding error codes from the staleness Seal Move package.
pub const STALE_FULLNODE_ERROR_CODE: u64 = 93492;
pub const STALE_KEY_SERVER_ERROR_CODE: u64 = 93493;
pub const STALENESS_MODULE: &str = "time";
pub const STALENESS_FUNCTION: &str = "check_staleness";

/// The kind of staleness detected by the on-chain `check_staleness` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    /// The fullnode's on-chain time lags the key server's time by more than the allowed amount.
    Fullnode,
    /// The key server's time lags the fullnode's on-chain time by more than the allowed amount.
    KeyServer,
}

#[derive(Debug)]
pub enum SealPackage {
    Testnet,
    Mainnet,
    Custom(ObjectID),
}

impl SealPackage {
    pub fn package_id(&self) -> ObjectID {
        match self {
            SealPackage::Testnet => ObjectID::from_hex_literal(TESTNET_PACKAGE_ID).unwrap(),
            SealPackage::Mainnet => ObjectID::from_hex_literal(MAINNET_PACKAGE_ID).unwrap(),
            SealPackage::Custom(seal_package) => *seal_package,
        }
    }

    /// Returns the kind of staleness if the simulation aborted in the staleness check of this
    /// package, or `None` otherwise.
    pub fn staleness_error(
        &self,
        simulate_response: &SimulateTransactionResponse,
    ) -> Option<Staleness> {
        let status = simulate_response.transaction().effects().status();
        if let Some(error) = &status.error
            && let Some(ErrorDetails::Abort(abort)) = &error.error_details
            && let Some(location) = &abort.location
            && location.package.as_deref() == Some(&self.package_id().to_string())
            && location.module.as_deref() == Some(STALENESS_MODULE)
        {
            return match abort.abort_code() {
                STALE_FULLNODE_ERROR_CODE => Some(Staleness::Fullnode),
                STALE_KEY_SERVER_ERROR_CODE => Some(Staleness::KeyServer),
                _ => None,
            };
        }
        None
    }

    pub fn add_staleness_check_to_ptb(
        &self,
        allowed_staleness: std::time::Duration,
        mut ptb: ProgrammableTransaction,
    ) -> Result<ProgrammableTransaction, InternalError> {
        let now = try_add_argument(&mut ptb, CallArg::from(current_epoch_time()))?;
        let allowed_staleness = try_add_argument(
            &mut ptb,
            CallArg::from(allowed_staleness.as_millis() as u64),
        )?;

        let clock = ptb
            .inputs
            .iter()
            .position(|arg| {
                matches!(
                    arg,
                    CallArg::Object(ObjectArg::SharedObject {
                        id: SUI_CLOCK_OBJECT_ID,
                        ..
                    })
                )
            })
            .map(try_argument_from_input_index)
            .unwrap_or_else(|| {
                // The clock is not yet part of the PTB, so we add it
                try_add_argument(&mut ptb, CallArg::CLOCK_IMM)
            })?;

        let staleness_check = Command::move_call(
            self.package_id(),
            Identifier::from_str(STALENESS_MODULE).unwrap(),
            Identifier::from_str(STALENESS_FUNCTION).unwrap(),
            vec![],
            vec![now, allowed_staleness, clock],
        );

        // This shifts all commands by 1 but that's okay since their results cannot be used as inputs
        ptb.commands.insert(0, staleness_check);
        Ok(ptb)
    }
}

fn try_argument_from_input_index(input_index: usize) -> Result<Argument, InternalError> {
    input_index
        .try_into()
        .map(Input)
        .map_err(|_| InternalError::InvalidPTB("Index out of bounds".to_string()))
}

fn try_add_argument(
    ptb: &mut ProgrammableTransaction,
    argument: CallArg,
) -> Result<Argument, InternalError> {
    ptb.inputs.push(argument);
    try_argument_from_input_index(ptb.inputs.len() - 1)
}
