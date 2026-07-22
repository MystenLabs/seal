// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::time::current_epoch_time;
use std::str::FromStr;
use sui_rpc::proto::sui::rpc::v2::execution_error::ErrorDetails;
use sui_rpc::proto::sui::rpc::v2::SimulateTransactionResponse;
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction, SharedInput,
};

/// Object id of the onchain Clock object.
const SUI_CLOCK_OBJECT_ID: Address = Address::from_static("0x6");
/// The Clock object's initial shared version.
const SUI_CLOCK_INITIAL_SHARED_VERSION: u64 = 1;

const TESTNET_PACKAGE_ID: &str =
    "0x8c1870cb43a490564f7e0df516098c74c5aa43c6c1b61b17dc99bc6a0bd9436d";
const MAINNET_PACKAGE_ID: &str =
    "0xbabb2b101000d2f3926ddc2e2b435f4e4c2c634f70eb5671919b0a907df9f2cf";

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
    Custom(Address),
}

impl SealPackage {
    pub fn package_id(&self) -> Address {
        match self {
            SealPackage::Testnet => Address::from_static(TESTNET_PACKAGE_ID),
            SealPackage::Mainnet => Address::from_static(MAINNET_PACKAGE_ID),
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
        let now = try_add_argument(&mut ptb, pure_input(&current_epoch_time())?)?;
        let allowed_staleness = try_add_argument(
            &mut ptb,
            pure_input(&(allowed_staleness.as_millis() as u64))?,
        )?;

        let clock = ptb
            .inputs
            .iter()
            .position(|arg| {
                matches!(arg, Input::Shared(shared) if shared.object_id() == SUI_CLOCK_OBJECT_ID)
            })
            .map(try_argument_from_input_index)
            .unwrap_or_else(|| {
                // The clock is not yet part of the PTB, so we add it
                try_add_argument(
                    &mut ptb,
                    Input::Shared(SharedInput::new(
                        SUI_CLOCK_OBJECT_ID,
                        SUI_CLOCK_INITIAL_SHARED_VERSION,
                        false,
                    )),
                )
            })?;

        let staleness_check = Command::MoveCall(MoveCall {
            package: self.package_id(),
            module: Identifier::from_str(STALENESS_MODULE).unwrap(),
            function: Identifier::from_str(STALENESS_FUNCTION).unwrap(),
            type_arguments: vec![],
            arguments: vec![now, allowed_staleness, clock],
        });

        // This shifts all commands by 1 but that's okay since their results cannot be used as inputs
        ptb.commands.insert(0, staleness_check);
        Ok(ptb)
    }
}

fn pure_input<T: serde::Serialize>(value: &T) -> Result<Input, InternalError> {
    bcs::to_bytes(value)
        .map(Input::Pure)
        .map_err(|e| InternalError::InvalidPTB(format!("Failed to serialize input: {e}")))
}

fn try_argument_from_input_index(input_index: usize) -> Result<Argument, InternalError> {
    input_index
        .try_into()
        .map(Argument::Input)
        .map_err(|_| InternalError::InvalidPTB("Index out of bounds".to_string()))
}

fn try_add_argument(
    ptb: &mut ProgrammableTransaction,
    input: Input,
) -> Result<Argument, InternalError> {
    ptb.inputs.push(input);
    try_argument_from_input_index(ptb.inputs.len() - 1)
}
