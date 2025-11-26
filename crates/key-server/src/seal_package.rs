// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::time::current_epoch_time;
use move_core_types::identifier::Identifier;
use std::str::FromStr;
use sui_sdk::rpc_types::{
    SuiExecutionStatus, SuiMoveAbort, SuiTransactionBlockEffects, SuiTransactionBlockEffectsV1,
};
use sui_types::base_types::ObjectID;
use sui_types::transaction::Argument::Input;
use sui_types::transaction::{CallArg, Command, ObjectArg, ProgrammableTransaction};
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

    fn staleness_module(&self) -> String {
        format!("{}::{}", self.package_id(), STALENESS_MODULE)
    }

    pub fn is_staleness_error(&self, effects: &SuiTransactionBlockEffects) -> bool {
        if let SuiTransactionBlockEffects::V1(SuiTransactionBlockEffectsV1 {
            status: SuiExecutionStatus::Failure { .. },
            abort_error:
                Some(SuiMoveAbort {
                    module_id: Some(module_id),
                    error_code: Some(error_code),
                    ..
                }),
            ..
        }) = effects
        {
            if error_code == &STALENESS_ERROR_CODE && module_id == &self.staleness_module() {
                return true;
            }
        }
        false
    }

    pub fn add_staleness_check_to_ptb(
        &self,
        allowed_staleness: std::time::Duration,
        mut ptb: ProgrammableTransaction,
    ) -> ProgrammableTransaction {
        let now = current_epoch_time();
        ptb.inputs.push(CallArg::from(now));
        let now_index = ptb.inputs.len() - 1;

        let allowed_staleness = allowed_staleness.as_millis() as u64;
        ptb.inputs.push(CallArg::from(allowed_staleness));
        let allowed_staleness_index = ptb.inputs.len() - 1;

        let clock_index = ptb
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
            .unwrap_or_else(|| {
                // The clock is not yet part of the PTB, so we add it
                ptb.inputs.push(CallArg::CLOCK_IMM);
                ptb.inputs.len() - 1
            });

        let staleness_check = Command::move_call(
            self.package_id(),
            Identifier::from_str(STALENESS_MODULE).unwrap(),
            Identifier::from_str(STALENESS_FUNCTION).unwrap(),
            vec![],
            vec![
                Input(now_index as u16),
                Input(allowed_staleness_index as u16),
                Input(clock_index as u16),
            ],
        );

        ptb.commands.insert(0, staleness_check);
        ptb
    }
}
