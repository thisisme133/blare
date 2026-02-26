use std::process::Command;

#[test]
fn fixture_pipeline_opt_in() {
    if std::env::var("BLARE_RUN_INTEGRATION").ok().as_deref() != Some("1") {
        eprintln!("Skipping integration pipeline test (set BLARE_RUN_INTEGRATION=1 to enable)");
        return;
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");

    let status = Command::new("bash")
        .arg("scripts/build_fixtures.sh")
        .current_dir(root)
        .status()
        .expect("failed to run build_fixtures.sh");
    assert!(status.success(), "build_fixtures.sh failed");

    let status = Command::new("bash")
        .arg("scripts/rewrite_fixtures.sh")
        .current_dir(root)
        .status()
        .expect("failed to run rewrite_fixtures.sh");
    assert!(status.success(), "rewrite_fixtures.sh failed");

    let status = Command::new("bash")
        .arg("scripts/verify_structure.sh")
        .current_dir(root)
        .status()
        .expect("failed to run verify_structure.sh");
    assert!(status.success(), "verify_structure.sh failed");

    if std::env::var("BLARE_RUN_WINE").ok().as_deref() == Some("1") {
        let status = Command::new("bash")
            .arg("scripts/run_wine_compare.sh")
            .current_dir(root)
            .status()
            .expect("failed to run run_wine_compare.sh");
        assert!(status.success(), "run_wine_compare.sh failed");
    }
}
