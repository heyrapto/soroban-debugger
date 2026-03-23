use crate::runtime::executor::ContractExecutor;
use crate::utils::wasm::{parse_instructions, WasmInstruction};
use crate::Result;
use serde::{Deserialize, Serialize};
use wasmparser::{Parser, Payload};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub location: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityReport {
    pub findings: Vec<SecurityFinding>,
}

pub trait SecurityRule {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn analyze_static(&self, _wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        Ok(vec![])
    }
    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        _trace: &[String],
    ) -> Result<Vec<SecurityFinding>> {
        Ok(vec![])
    }
}

pub struct SecurityAnalyzer {
    rules: Vec<Box<dyn SecurityRule>>,
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(HardcodedAddressRule),
                Box::new(ArithmeticCheckRule),
                Box::new(AuthorizationCheckRule),
                Box::new(ReentrancyPatternRule),
                Box::new(UnboundedIterationRule),
            ],
        }
    }

    pub fn analyze(
        &self,
        wasm_bytes: &[u8],
        executor: Option<&ContractExecutor>,
        trace: Option<&[String]>,
    ) -> Result<SecurityReport> {
        let mut report = SecurityReport::default();

        for rule in &self.rules {
            // Static analysis
            let static_findings = rule.analyze_static(wasm_bytes)?;
            report.findings.extend(static_findings);

            // Dynamic analysis
            if let (Some(exec), Some(tr)) = (executor, trace) {
                let dynamic_findings = rule.analyze_dynamic(exec, tr)?;
                report.findings.extend(dynamic_findings);
            }
        }

        Ok(report)
    }
}

impl Default for SecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// --- Rules ---

struct HardcodedAddressRule;
impl SecurityRule for HardcodedAddressRule {
    fn name(&self) -> &str {
        "hardcoded-address"
    }
    fn description(&self) -> &str {
        "Detects hardcoded addresses in WASM bytes."
    }

    fn analyze_static(&self, wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        // Simple heuristic: look for G... or C... strings of appropriate length
        // This is a basic implementation.
        let parser = Parser::new(0);
        for payload in parser.parse_all(wasm_bytes).flatten() {
            if let Payload::DataSection(reader) = payload {
                for data in reader.into_iter().flatten() {
                    let content = String::from_utf8_lossy(data.data);
                    // Check for Stellar address patterns (G... or C...)
                    // Standard Stellar addresses are 56 chars.
                    for word in content.split(|c: char| !c.is_alphanumeric()) {
                        if (word.starts_with('G') || word.starts_with('C')) && word.len() == 56 {
                            findings.push(SecurityFinding {
                                rule_id: self.name().to_string(),
                                severity: Severity::Medium,
                                location: "Data Section".to_string(),
                                description: format!("Found potential hardcoded address: {}", word),
                                remediation: "Use Address::from_str from a configuration or argument instead of hardcoding.".to_string(),
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

struct ArithmeticCheckRule;
impl SecurityRule for ArithmeticCheckRule {
    fn name(&self) -> &str {
        "arithmetic-overflow"
    }
    fn description(&self) -> &str {
        "Detects potential for unchecked arithmetic overflow."
    }

    fn analyze_static(&self, wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        let instructions = parse_instructions(wasm_bytes);

        for (i, instr) in instructions.iter().enumerate() {
            if Self::is_arithmetic(instr) && !Self::is_guarded(&instructions, i) {
                findings.push(SecurityFinding {
                    rule_id: self.name().to_string(),
                    severity: Severity::Medium,
                    location: format!("Instruction {}", i),
                    description: format!(
                        "Unchecked arithmetic operation detected: {:?}",
                        instr
                    ),
                    remediation: "Ensure arithmetic operations are guarded with proper bounds checks or overflow handling.".to_string(),
                });
            }
        }

        Ok(findings)
    }
}

impl ArithmeticCheckRule {
    /// Check if an instruction is an arithmetic operation.
    fn is_arithmetic(instr: &WasmInstruction) -> bool {
        matches!(
            instr,
            WasmInstruction::I32Add
                | WasmInstruction::I32Sub
                | WasmInstruction::I32Mul
                | WasmInstruction::I64Add
                | WasmInstruction::I64Sub
                | WasmInstruction::I64Mul
        )
    }

    /// Check if an arithmetic operation is guarded by control flow or external function call.
    fn is_guarded(instructions: &[WasmInstruction], idx: usize) -> bool {
        let start = idx.saturating_sub(2);
        let end = (idx + 3).min(instructions.len());

        for i in start..end {
            match instructions[i] {
                WasmInstruction::If | WasmInstruction::BrIf | WasmInstruction::Call => {
                    return true
                }
                _ => {}
            }
        }

        false
    }
}

struct AuthorizationCheckRule;
impl SecurityRule for AuthorizationCheckRule {
    fn name(&self) -> &str {
        "missing-auth"
    }
    fn description(&self) -> &str {
        "Detects sensitive functions that might be missing authorization checks."
    }

    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        _trace: &[String],
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        // Heuristic: If a function writes to storage but no 'require_auth' was seen in the trace.
        // This requires parsing the diagnostic events / traces.
        // For now, let's assume 'trace' contains event names.
        let mut auth_seen = false;
        let mut storage_write_seen = false;

        for entry in _trace {
            if entry.contains("require_auth") || entry.contains("authorized") {
                auth_seen = true;
            }
            if entry.contains("contract_storage_put") || entry.contains("contract_storage_update") {
                storage_write_seen = true;
            }
        }

        if storage_write_seen && !auth_seen {
            findings.push(SecurityFinding {
                rule_id: self.name().to_string(),
                severity: Severity::High,
                location: "Execution Trace".to_string(),
                description: "Storage mutation detected without preceding authorization check."
                    .to_string(),
                remediation: "Ensure all sensitive functions call `address.require_auth()`."
                    .to_string(),
            });
        }

        Ok(findings)
    }
}

struct ReentrancyPatternRule;
impl SecurityRule for ReentrancyPatternRule {
    fn name(&self) -> &str {
        "reentrancy-pattern"
    }
    fn description(&self) -> &str {
        "Detects cross-contract calls followed by storage writes."
    }

    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        _trace: &[String],
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        let mut cross_call_seen = false;

        for (i, entry) in _trace.iter().enumerate() {
            if entry.contains("call_contract") || entry.contains("invoke_contract") {
                cross_call_seen = true;
            }
            if cross_call_seen
                && (entry.contains("contract_storage_put")
                    || entry.contains("contract_storage_update"))
            {
                findings.push(SecurityFinding {
                    rule_id: self.name().to_string(),
                    severity: Severity::Medium,
                    location: format!("Trace line {}", i),
                    description: "Storage write detected after an external contract call. Possible reentrancy risk.".to_string(),
                    remediation: "Follow the checks-effects-interactions pattern: update state before making external calls.".to_string(),
                });
                // Reset to avoid duplicate flags for the same sequence if desired, or keep flagging.
            }
        }
        Ok(findings)
    }
}

struct UnboundedIterationRule;
impl SecurityRule for UnboundedIterationRule {
    fn name(&self) -> &str {
        "unbounded-iteration"
    }
    fn description(&self) -> &str {
        "Detects storage iterations that might be unbounded."
    }

    fn analyze_static(&self, _wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        // Look for loops that call storage get/has in a way that suggests iteration.
        // Again, hard without control flow graph.
        Ok(vec![])
    }

    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        _trace: &[String],
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        let mut storage_read_count = 0;
        for entry in _trace {
            if entry.contains("contract_storage_get") || entry.contains("contract_storage_has") {
                storage_read_count += 1;
            }
        }

        if storage_read_count > 50 {
            findings.push(SecurityFinding {
                rule_id: self.name().to_string(),
                severity: Severity::Low,
                location: "Execution Trace".to_string(),
                description: format!("High number of storage reads ({}) detected. Could lead to out-of-gas for large datasets.", storage_read_count),
                remediation: "Avoid unbounded iteration over storage. Use pagination or mapping where possible.".to_string(),
            });
        }
        Ok(findings)
    }
}
