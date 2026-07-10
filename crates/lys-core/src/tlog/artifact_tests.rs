#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::error::TrustError;

#[test]
fn format_constants_are_frozen_strings() {
    assert_eq!(INCLUSION_PROOF_FORMAT, "lys/log-inclusion-proof/v1");
    assert_eq!(CONSISTENCY_PROOF_FORMAT, "lys/log-consistency-proof/v1");
    assert_eq!(MAX_JSON_TREE_SIZE, 9_007_199_254_740_992);
}

/// §6.5: the 2^53 guard at the exact boundary.
#[test]
fn json_safe_tree_size_guard_boundary() {
    check_json_safe_tree_size(0).unwrap();
    check_json_safe_tree_size(MAX_JSON_TREE_SIZE - 1).unwrap();

    for at_or_beyond in [MAX_JSON_TREE_SIZE, MAX_JSON_TREE_SIZE + 1, u64::MAX] {
        let err = check_json_safe_tree_size(at_or_beyond).unwrap_err();
        assert!(
            matches!(err, TrustError::LogArtifactEncoding { .. }),
            "size: {at_or_beyond}"
        );
    }
}

fn sample_inclusion_json() -> String {
    r#"{
        "format": "lys/log-inclusion-proof/v1",
        "tree_size": 3,
        "leaf_index": 1,
        "hashes": ["MF31n5WQw8msY9KydDw4jjeSRJB4zr9/s9vmRxZDsrc="],
        "checkpoint": "example.com/lys/test\n3\nroot\n\n— k s\n"
    }"#
    .to_string()
}

#[test]
fn inclusion_artifact_json_round_trips_with_field_order() {
    let artifact: InclusionProofArtifact = serde_json::from_str(&sample_inclusion_json()).unwrap();
    assert_eq!(artifact.format, INCLUSION_PROOF_FORMAT);
    assert_eq!(artifact.tree_size, 3);
    assert_eq!(artifact.leaf_index, 1);

    // Field declaration order IS the serialization order (D2 shape).
    let emitted = serde_json::to_string(&artifact).unwrap();
    let positions: Vec<usize> = [
        "\"format\"",
        "\"tree_size\"",
        "\"leaf_index\"",
        "\"hashes\"",
        "\"checkpoint\"",
    ]
    .iter()
    .map(|field| emitted.find(field).unwrap())
    .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn consistency_artifact_json_field_order() {
    let artifact = ConsistencyProofArtifact {
        format: CONSISTENCY_PROOF_FORMAT.to_string(),
        tree_size_1: 2,
        tree_size_2: 3,
        hashes: vec![],
        checkpoint_1: "a\n".to_string(),
        checkpoint_2: "b\n".to_string(),
    };
    let emitted = serde_json::to_string(&artifact).unwrap();
    let positions: Vec<usize> = [
        "\"format\"",
        "\"tree_size_1\"",
        "\"tree_size_2\"",
        "\"hashes\"",
        "\"checkpoint_1\"",
        "\"checkpoint_2\"",
    ]
    .iter()
    .map(|field| emitted.find(field).unwrap())
    .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn unknown_fields_are_rejected() {
    let with_unknown = sample_inclusion_json().replacen(
        "\"tree_size\": 3,",
        "\"tree_size\": 3, \"smuggled\": true,",
        1,
    );
    assert!(serde_json::from_str::<InclusionProofArtifact>(&with_unknown).is_err());
}

#[test]
fn duplicate_json_keys_are_rejected() {
    let with_duplicate = sample_inclusion_json().replacen(
        "\"tree_size\": 3,",
        "\"tree_size\": 3, \"tree_size\": 9,",
        1,
    );
    assert!(serde_json::from_str::<InclusionProofArtifact>(&with_duplicate).is_err());
}

#[test]
fn non_integer_and_negative_sizes_are_rejected() {
    for bad in ["3.0", "-3", "\"3\"", "3e0"] {
        let text = sample_inclusion_json().replacen(
            "\"tree_size\": 3,",
            &format!("\"tree_size\": {bad},"),
            1,
        );
        assert!(
            serde_json::from_str::<InclusionProofArtifact>(&text).is_err(),
            "tree_size: {bad}"
        );
    }
}

#[test]
fn artifact_kinds_do_not_cross_deserialize() {
    // An inclusion artifact's JSON does not satisfy the consistency shape
    // and vice versa (distinct field sets + deny_unknown_fields).
    assert!(serde_json::from_str::<ConsistencyProofArtifact>(&sample_inclusion_json()).is_err());

    let consistency = ConsistencyProofArtifact {
        format: CONSISTENCY_PROOF_FORMAT.to_string(),
        tree_size_1: 2,
        tree_size_2: 3,
        hashes: vec![],
        checkpoint_1: "a\n".to_string(),
        checkpoint_2: "b\n".to_string(),
    };
    let consistency_json = serde_json::to_string(&consistency).unwrap();
    assert!(serde_json::from_str::<InclusionProofArtifact>(&consistency_json).is_err());
}
