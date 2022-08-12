use crate::contract_wrapper_trait::ContractWrapper;
use near_units::*;
use workspaces::operations::Function;
use workspaces::prelude::*;
use workspaces::{network::Sandbox, Account, Contract, Worker};
use tokio::runtime::Runtime;
use near_primitives::types::AccountId;
use std::error::Error;
use near_crypto::KeyType::ED25519;
use near_crypto::PublicKey;
use near_primitives::errors::{ActionError, ActionErrorKind, TxExecutionError};
use near_sdk::{Balance, Gas};
use near_primitives::views::{ExecutionOutcomeView, ExecutionOutcomeWithIdView, ExecutionStatusView, FinalExecutionOutcomeView, FinalExecutionStatus, SignedTransactionView};
use workspaces::result::CallExecutionDetails;

//https://github.com/near/workspaces-rs
pub struct SandboxContractWrapper {
    signer_account: Account,
    contract: Contract,
    worker: Worker<Sandbox>,
}

impl SandboxContractWrapper {
    pub fn new(signer_account: Account, contract: Contract, worker: Worker<Sandbox>) -> Self {
        SandboxContractWrapper {
            signer_account,
            contract,
            worker
        }
    }

    fn from_call_execution_details(call_execution_details: CallExecutionDetails) -> FinalExecutionOutcomeView {
        let status = match call_execution_details.is_success() {
            true => FinalExecutionStatus::SuccessValue("".to_string()),
            false => FinalExecutionStatus::Failure(TxExecutionError::ActionError(ActionError { index: None, kind: ActionErrorKind::AccountAlreadyExists { account_id: "fail.testnet".parse().unwrap() } })),
        };

        let outcome = call_execution_details.outcome();

        FinalExecutionOutcomeView {
            status: status,
            transaction: SignedTransactionView {
                signer_id: "fack_signature_id".parse().unwrap(),
                public_key: PublicKey::empty(ED25519),
                nonce: 0,
                receiver_id: "fack_receiver_id".parse().unwrap(),
                actions: vec![],
                signature: Default::default(),
                hash: Default::default()
            },
            transaction_outcome: ExecutionOutcomeWithIdView {
                proof: vec![],
                block_hash: Default::default(),
                id: Default::default(),
                outcome: ExecutionOutcomeView{
                    logs: outcome.clone().logs,
                    receipt_ids: vec![],
                    gas_burnt: outcome.gas_burnt,
                    tokens_burnt: outcome.tokens_burnt,
                    executor_id: outcome.clone().executor_id,
                    status: ExecutionStatusView::Unknown,
                    metadata: Default::default()
                },
            },
            receipts_outcome: vec![]
        }
    }
}

impl ContractWrapper for SandboxContractWrapper {
    fn call_view_function(
        &self,
        method_name: String,
        args: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let rt = Runtime::new()?;

        Ok(rt.block_on(self.contract
            .view(&self.worker, &method_name, args)).unwrap().result)
    }

    fn call_change_method_batch(
        &self,
        method_name: Vec<String>,
        args: Vec<Vec<u8>>,
        deposit: Option<Vec<Balance>>,
        gas: Option<Gas>,
    ) -> Result<FinalExecutionOutcomeView, Box<dyn Error>> {
        let deposit = deposit.unwrap();
        for i in 0..method_name.len() - 1 {
            self.call_change_method(method_name[i].clone(), args[i].clone(), Some(deposit[i]), gas);
        }

        self.call_change_method(method_name[method_name.len() - 1].clone(), args[method_name.len() - 1].clone(), Some(deposit[method_name.len() - 1]), gas)
    }

    fn call_change_method(
        &self,
        method_name: String,
        args: Vec<u8>,
        deposit: Option<Balance>,
        gas: Option<Gas>,
    ) -> Result<FinalExecutionOutcomeView, Box<dyn Error>> {
        let rt = Runtime::new()?;

        Ok(Self::from_call_execution_details(rt.block_on(self.signer_account
            .call(&self.worker, self.contract.id(), &method_name)
            .args(args)
            .transact()).unwrap()))
    }

    fn get_account_id(&self) -> AccountId {
        self.contract.id().clone()
    }
}
