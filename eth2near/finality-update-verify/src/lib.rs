use bitvec::order::Lsb0;
use bitvec::prelude::BitVec;
use eth2_utility::consensus::*;
use eth2_utility::consensus::{
    compute_domain, compute_signing_root, compute_sync_committee_period, get_participant_pubkeys,
    Network, NetworkConfig, DOMAIN_SYNC_COMMITTEE, MIN_SYNC_COMMITTEE_PARTICIPANTS,
};
use eth_types::eth2::{LightClientState, LightClientUpdate};
use std::error::Error;
use std::str::FromStr;
use tree_hash::TreeHash;

#[cfg(test)]
pub mod config_for_tests;

pub fn validate_light_client_update(
    state: &LightClientState,
    network: &str,
    update: &LightClientUpdate,
) -> Result<(), Box<dyn Error>> {
    let config = NetworkConfig::new(&Network::from_str(network)?);
    let finalized_period = compute_sync_committee_period(state.finalized_beacon_header.header.slot);
    verify_finality_branch(state, update, finalized_period, &config)?;

    // Verify sync committee has sufficient participants
    let sync_committee_bits =
        BitVec::<u8, Lsb0>::from_slice(&update.sync_aggregate.sync_committee_bits.0);
    let sync_committee_bits_sum: u64 = sync_committee_bits.count_ones().try_into()?;

    if sync_committee_bits_sum < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return Err("Invalid sync committee bits sum: {}")?;
    }

    if sync_committee_bits_sum * 3 < (sync_committee_bits.len() * 2).try_into()? {
        return Err("Sync committee bits sum is less than 2/3 threshold")?;
    }

    if !verify_bls_signatures(state, update, &config)? {
        return Err("Failed to verify the bls signature")?;
    }

    Ok(())
}

pub fn verify_bls_signatures(
    state: &LightClientState,
    update: &LightClientUpdate,
    config: &NetworkConfig,
) -> Result<bool, Box<dyn Error>> {
    let finalized_period = compute_sync_committee_period(state.finalized_beacon_header.header.slot);
    let signature_period = compute_sync_committee_period(update.signature_slot);

    // Verify signature period does not skip a sync committee period
    if signature_period != finalized_period && signature_period != finalized_period + 1 {
        return Err(format!(
            "The acceptable signature periods are '{}' and '{}' but got {}",
            finalized_period,
            finalized_period + 1,
            signature_period
        ))?;
    }

    // Verify sync committee aggregate signature
    let sync_committee = if signature_period == finalized_period {
        &state.current_sync_committee
    } else {
        &state.next_sync_committee
    };

    let sync_committee_bits =
        BitVec::<u8, Lsb0>::from_slice(&update.sync_aggregate.sync_committee_bits.0);
    let participant_pubkeys =
        get_participant_pubkeys(&sync_committee.pubkeys.0, &sync_committee_bits);
    let fork_version = config
        .compute_fork_version_by_slot(update.signature_slot)
        .ok_or("Unsupported fork")?;
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        fork_version,
        config.genesis_validators_root.into(),
    );
    let signing_root = compute_signing_root(
        eth_types::H256(update.attested_beacon_header.tree_hash_root()),
        domain,
    );

    let aggregate_signature =
        bls::AggregateSignature::deserialize(&update.sync_aggregate.sync_committee_signature.0)
            .map_err(|_| "Failed to deserialize sync committee signature")?;
    let pubkeys: Vec<bls::PublicKey> = participant_pubkeys
        .iter()
        .map(|x| bls::PublicKey::deserialize(&x.0))
        .collect::<Result<_, _>>()
        .map_err(|_| "Failed to deserialize PublicKey")?;

    Ok(aggregate_signature
        .fast_aggregate_verify(signing_root.0, &pubkeys.iter().collect::<Vec<_>>()))
}

fn verify_finality_branch(
    state: &LightClientState,
    update: &LightClientUpdate,
    finalized_period: u64,
    config: &NetworkConfig,
) -> Result<(), Box<dyn Error>> {
    // The active header will always be the finalized header because we don't accept updates without the finality update.
    let active_header = &update.finality_update.header_update.beacon_header;

    if active_header.slot <= state.finalized_beacon_header.header.slot {
        return Err("The active header slot number should be higher than the finalized slot")?;
    }

    if update.attested_beacon_header.slot < update.finality_update.header_update.beacon_header.slot
    {
        return Err(
            "The attested header slot should be equal to or higher than the finalized header slot",
        )?;
    }

    if update.signature_slot <= update.attested_beacon_header.slot {
        return Err("The signature slot should be higher than the attested header slot")?;
    }

    let update_period = compute_sync_committee_period(active_header.slot);
    assert!(
        update_period == finalized_period || update_period == finalized_period + 1,
        "The acceptable update periods are '{}' and '{}' but got {}",
        finalized_period,
        finalized_period + 1,
        update_period
    );

    // Verify that the `finality_branch`, confirms `finalized_header`
    // to match the finalized checkpoint root saved in the state of `attested_header`.
    if !verify_merkle_proof(
        update
            .finality_update
            .header_update
            .beacon_header
            .tree_hash_root()
            .into(),
        &update.finality_update.finality_branch,
        FINALITY_TREE_DEPTH.try_into()?,
        FINALITY_TREE_INDEX.try_into()?,
        update.attested_beacon_header.state_root,
    ) {
        return Err("Invalid finality proof")?;
    }

    if !config.validate_beacon_block_header_update(&update.finality_update.header_update) {
        return Err("Invalid execution block hash proof")?;
    }

    // Verify that the `next_sync_committee`, if present, actually is the next sync committee saved in the
    // state of the `active_header`
    if update_period != finalized_period {
        let sync_committee_update = update
            .sync_committee_update
            .as_ref()
            .ok_or("The sync committee update is missed")?;

        if !verify_merkle_proof(
            sync_committee_update
                .next_sync_committee
                .tree_hash_root()
                .into(),
            &sync_committee_update.next_sync_committee_branch,
            SYNC_COMMITTEE_TREE_DEPTH.try_into()?,
            SYNC_COMMITTEE_TREE_INDEX.try_into()?,
            update.attested_beacon_header.state_root,
        ) {
            return Err("Invalid next sync committee proof")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_for_tests::ConfigForTests;
    use eth_types::eth2::LightClientUpdate;
    use eth_types::eth2::SyncCommittee;

    fn get_config() -> ConfigForTests {
        ConfigForTests::load_from_toml("config_for_tests.toml".try_into().unwrap())
    }

    #[test]
    fn smoke_verify_finality_update() {
        let config = get_config();

        let light_client_updates: Vec<LightClientUpdate> = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_light_client_updates)
                .expect("Unable to read file"),
        )
        .unwrap();

        let current_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_current_sync_committee.clone())
                .expect("Unable to read file"),
        )
        .unwrap();
        let next_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_next_sync_committee.clone())
                .expect("Unable to read file"),
        )
        .unwrap();

        assert!(is_correct_finality_update(
            &config.network_name,
            &light_client_updates[0],
            current_sync_committee
        )
        .unwrap());

        assert!(!is_correct_finality_update(
            &config.network_name,
            &light_client_updates[0],
            next_sync_committee
        )
        .unwrap());
    }
}
