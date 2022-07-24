use std::error::Error;
use eth_types::eth2::{ExtendedBeaconBlockHeader, LightClientUpdate, SyncCommittee};
use std::vec::Vec;
use std::string::String;
use borsh::BorshDeserialize;
use eth_types::{BlockHeader, H256};
use near_crypto::InMemorySigner;
use near_jsonrpc_client::JsonRpcClient;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_client::methods;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_primitives::types::{AccountId, BlockReference, Finality, FunctionArgs};
use serde_json::{json, Value};
use tokio::runtime::Runtime;
use near_primitives::borsh::BorshSerialize;
use near_primitives::views::QueryRequest;
use std::option::Option;
use near_sdk::{Balance, ONE_NEAR};

pub struct EthClientContract {
    last_slot: u64,
    client: JsonRpcClient,
    contract_account: AccountId,
    signer: InMemorySigner,
    account_id: String,
}

impl EthClientContract {
    pub fn new(near_endpoint: &str, account_id: &str,
               path_to_signer_secret_key: &str, contract_account_id: &str,
               last_slot: u64) -> Self {
        let client = JsonRpcClient::connect(near_endpoint);
        let contract_account = contract_account_id.parse().unwrap();

        let signer_account_id = account_id.parse().unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path_to_signer_secret_key).expect("Unable to read file")).unwrap();
        let signer_secret_key = serde_json::to_string(&v["private_key"]).unwrap();
        let signer_secret_key = &signer_secret_key[1..signer_secret_key.len() - 1];

        let signer = InMemorySigner::from_secret_key(signer_account_id, signer_secret_key.parse().unwrap());

        EthClientContract {
            last_slot: last_slot,
            client,
            contract_account,
            signer,
            account_id: account_id.to_string(),
        }
    }

    pub fn get_last_submitted_slot(&self) -> u64 {
        return self.last_slot;
    }

    pub fn is_known_block(&self, execution_block_hash: &H256) -> Result<bool, Box<dyn Error>> {
        let result = self.call_view_function("is_known_execution_header".to_string(), execution_block_hash.try_to_vec()?)?;
        let is_known: bool = bool::try_from_slice(&result)?;
        Ok(is_known)
    }

    pub fn send_light_client_update(& mut self, light_client_update: LightClientUpdate) -> Result<(), Box<dyn Error>> {
        self.call_change_method(vec!["submit_update".to_string()], vec![light_client_update.try_to_vec()?], vec![0])
    }

    pub fn get_finalized_beacon_block_hash(&self) -> Result<H256, Box<dyn Error>> {
        let result = self.call_view_function("finalized_beacon_block_root".to_string(), json!({}).to_string().into_bytes())?;
        let beacon_block_hash: H256 = H256::try_from_slice(&result)?;
        Ok(beacon_block_hash)
    }

    pub fn send_headers(& mut self, headers: &Vec<BlockHeader>, end_slot: u64) -> Result<(), Box<dyn std::error::Error>> {
        self.last_slot = end_slot;

        let method_names = vec!["submit_header".to_string(); headers.len()];
        let mut args = Vec::new();
        let deposits = vec![0 as u128; headers.len()];

        for header in headers {
            args.push(header.try_to_vec()?);
        }
        self.call_change_method(method_names, args, deposits)?;
        Ok(())
    }

    pub fn register(&self) -> Result<(), Box<dyn Error>> {
        self.call_change_method(vec!["register_submitter".to_string()], vec![json!({
            "account_id": self.account_id,
        }).to_string().into_bytes()], vec![10*ONE_NEAR])
    }

    pub fn init_contract(&self, network: String, finalized_execution_header: BlockHeader,
                         finalized_beacon_header: ExtendedBeaconBlockHeader,
                         current_sync_committee: SyncCommittee,
                         next_sync_committee: SyncCommittee) {
        #[derive(BorshSerialize)]
        pub struct InitInput {
            pub network: String,
            pub finalized_execution_header: BlockHeader,
            pub finalized_beacon_header: ExtendedBeaconBlockHeader,
            pub current_sync_committee: SyncCommittee,
            pub next_sync_committee: SyncCommittee,
            pub validate_updates: bool,
            pub verify_bls_signatures: bool,
            pub hashes_gc_threshold: u64,
            pub max_submitted_blocks_by_account: u32,
            pub trusted_signer: Option<AccountId>,
        }

        let init_input = InitInput {
            network,
            finalized_execution_header,
            finalized_beacon_header,
            current_sync_committee,
            next_sync_committee,
            validate_updates: true,
            verify_bls_signatures: false,
            hashes_gc_threshold: 51000,
            max_submitted_blocks_by_account: 8000,
            trusted_signer: Option::<AccountId>::None,
        };

        self.call_change_method(vec!["init".to_string()], vec![init_input.try_to_vec().unwrap()], vec![0]).unwrap();
    }

    fn call_view_function(&self, method_name: String, args: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let rt = Runtime::new()?;
        let handle = rt.handle();

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: self.contract_account.clone(),
                method_name,
                args: FunctionArgs::from(args),
            },
        };

        let response =  handle.block_on(self.client.call(request))?;

        if let QueryResponseKind::CallResult(result) = response.kind {
            return Ok(result.result)
        } else {
            return Err("view method doesn't return any result")?;
        }
    }

    fn call_change_method(&self, method_name: Vec<String>, args: Vec<Vec<u8>>, deposit: Vec<Balance>) -> Result<(), Box<dyn std::error::Error>> {
        let rt = Runtime::new()?;
        let handle = rt.handle();

        let access_key_query_response = handle.block_on(self.client
            .call(methods::query::RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: near_primitives::views::QueryRequest::ViewAccessKey {
                    account_id: self.signer.account_id.clone(),
                    public_key: self.signer.public_key.clone(),
                },
            }))?;

        let current_nonce = match access_key_query_response.kind {
            QueryResponseKind::AccessKey(access_key) => access_key.nonce,
            _ => Err("failed to extract current nonce")?,
        };

        let mut actions = Vec::new();
        for i in 0..method_name.len() {
            actions.push(
                Action::FunctionCall(FunctionCallAction{
                    method_name: method_name[i].clone(),
                    args: args[i].clone(),
                    gas: 75_000_000_000_000, // 75 TeraGas
                    deposit: deposit[i].clone(),
                })
            );
        }

        let transaction = Transaction {
            signer_id: self.signer.account_id.clone(),
            public_key: self.signer.public_key.clone(),
            nonce: current_nonce + 1,
            receiver_id: self.contract_account.clone(),
            block_hash: access_key_query_response.block_hash,
            actions,
        };

        let request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction: transaction.sign(&self.signer),
        };
        
        handle.block_on(self.client.call(&request))?;
        Ok(())
    }
}
