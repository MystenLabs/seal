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
    "0x4016869413374eaa71df2a043d1660ed7bc927ab7962831f8b07efbc7efdb2c3";
const MAINNET_PACKAGE_ID: &str =
    "0xcb83a248bda5f7a0a431e6bf9e96d184e604130ec5218696e3f1211113b447b7";

/// This should be equal to the corresponding error code from the staleness Seal Move package.
pub const STALENESS_ERROR_CODE: u64 = 93492;
pub const STALENESS_MODULE: &str = "time";
pub const STALENESS_FUNCTION: &str = "check_staleness";

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

    pub fn is_staleness_error(&self, simulate_response: &SimulateTransactionResponse) -> bool {
        let status = simulate_response.transaction().effects().status();
        if let Some(error) = &status.error
            && let Some(ErrorDetails::Abort(abort)) = &error.error_details
            && abort.abort_code() == STALENESS_ERROR_CODE
            && let Some(location) = &abort.location
            && location.package.as_deref() == Some(&self.package_id().to_string())
            && location.module.as_deref() == Some(STALENESS_MODULE)
        {
            return true;
        }
        false
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
