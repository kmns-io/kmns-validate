use kmns_contract::{Contract, ContractLimits};

#[test]
fn static_development_contracts_compile() {
    let artifacts = [include_str!("fixtures/sample_contract.yaml")];

    for artifact in artifacts {
        let contract = Contract::parse(artifact.as_bytes(), &ContractLimits::default()).unwrap();
        assert!(!contract.checks.is_empty());
    }
}
