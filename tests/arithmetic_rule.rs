use soroban_debugger::analyzer::security::SecurityAnalyzer;
use soroban_debugger::utils::wasm::{parse_instructions, WasmInstruction};

#[test]
fn test_parse_instructions_recognizes_arithmetic() {
    let wasm = vec![0x6A]; // i32.add
    let instructions = parse_instructions(&wasm);
    assert_eq!(instructions.len(), 1);
    assert_eq!(instructions[0], WasmInstruction::I32Add);
}

#[test]
fn test_parse_instructions_recognizes_control_flow() {
    let wasm = vec![0x04, 0x0D]; // if, br_if
    let instructions = parse_instructions(&wasm);
    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[0], WasmInstruction::If);
    assert_eq!(instructions[1], WasmInstruction::BrIf);
}

#[test]
fn test_parse_instructions_handles_unknown() {
    let wasm = vec![0xFF, 0xAB];
    let instructions = parse_instructions(&wasm);
    assert_eq!(instructions.len(), 2);
    assert!(matches!(instructions[0], WasmInstruction::Unknown(0xFF)));
    assert!(matches!(instructions[1], WasmInstruction::Unknown(0xAB)));
}

#[test]
fn test_detects_unchecked_arithmetic() {
    // Single i32.add with no guard
    let wasm = vec![0x6A];
    let analyzer = SecurityAnalyzer::new();
    let report = analyzer.analyze(&wasm, None, None).expect("analysis failed");

    assert!(!report.findings.is_empty(), "Should detect unchecked arithmetic");
    let finding = &report.findings[0];
    assert_eq!(finding.rule_id, "arithmetic-overflow");
}

#[test]
fn test_ignores_guarded_arithmetic() {
    // If followed by i32.add: control flow guard
    let wasm = vec![0x04, 0x6A];
    let analyzer = SecurityAnalyzer::new();
    let report = analyzer.analyze(&wasm, None, None).expect("analysis failed");

    // Should not flag the add as unchecked because it's guarded by if
    let arithmetic_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "arithmetic-overflow")
        .collect();
    assert!(
        arithmetic_findings.is_empty(),
        "Should not flag guarded arithmetic"
    );
}

#[test]
fn test_ignores_call_guarded_arithmetic() {
    // Call (0x10) followed by i32.add: external function guard
    let wasm = vec![0x10, 0x6A];
    let analyzer = SecurityAnalyzer::new();
    let report = analyzer.analyze(&wasm, None, None).expect("analysis failed");

    let arithmetic_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "arithmetic-overflow")
        .collect();
    assert!(
        arithmetic_findings.is_empty(),
        "Should not flag call-guarded arithmetic"
    );
}

#[test]
fn test_avoids_false_positives() {
    // Random non-arithmetic bytes
    let wasm = vec![0x00, 0x01, 0x02, 0x03];
    let analyzer = SecurityAnalyzer::new();
    let report = analyzer.analyze(&wasm, None, None).expect("analysis failed");

    let arithmetic_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "arithmetic-overflow")
        .collect();
    assert!(arithmetic_findings.is_empty(), "Should not flag non-arithmetic");
}

#[test]
fn test_detects_all_arithmetic_types() {
    // Test all arithmetic instruction types
    let arithmetic_opcodes = vec![0x6A, 0x6B, 0x6C, 0x7C, 0x7D, 0x7E];

    for opcode in arithmetic_opcodes {
        let wasm = vec![opcode];
        let analyzer = SecurityAnalyzer::new();
        let report = analyzer.analyze(&wasm, None, None).expect("analysis failed");

        let arithmetic_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "arithmetic-overflow")
            .collect();
        assert!(
            !arithmetic_findings.is_empty(),
            "Should detect arithmetic opcode: 0x{:X}",
            opcode
        );
    }
}

#[test]
fn test_multiple_unguarded_arithmetic() {
    // Multiple unguarded arithmetic operations
    let wasm = vec![0x6A, 0x01, 0x6B];
    let analyzer = SecurityAnalyzer::new();
    let report = analyzer.analyze(&wasm, None, None).expect("analysis failed");

    let arithmetic_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "arithmetic-overflow")
        .collect();
    assert_eq!(arithmetic_findings.len(), 2, "Should detect both arithmetic ops");
}
