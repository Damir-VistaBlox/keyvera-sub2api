package securityaudit

// Shared test fixture builders with no DB/Redis dependency, used by both the
// unit suite (prompt_worker_test.go, prompt_config_test.go) and the
// integration suite (prompt_repository_integration_test.go,
// prompt_config_integration_test.go) — kept untagged so both builds see them.

func integrationResult(decision EventDecision) *NormalizedResult {
	result := &NormalizedResult{
		Decision: decision, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		Categories: []string{}, MatchedScanners: []string{}, ScannerScores: map[string]float64{},
		ScannerEvidence: map[string]string{}, ScannerBackend: "qwen3guard-openai",
		ScannerVersion: "test", GuardEndpointID: "guard-1", PolicyID: "priority",
		PolicyVersion: 1, ChunkTotal: 1, LatencyMS: 2,
	}
	if decision != EventPass {
		result.RiskLevel = RiskCritical
		result.Action = ActionBlock
		result.Safety = "Unsafe"
		result.Categories = []string{"pii"}
		result.MatchedScanners = []string{"pii"}
		result.ScannerScores["pii"] = 1
		result.ScannerEvidence["pii"] = "redacted evidence"
	}
	return result
}

func promptAuditUpdateRequest(version int64, workerCount int, token string) UpdateConfigRequest {
	return UpdateConfigRequest{
		ExpectedConfigVersion: version, Enabled: true, BlockingEnabled: false, StorePassEvents: false,
		Strategy: "priority", WorkerCount: workerCount, QueueCapacity: 64, Scanners: []string{"pii", "jailbreak"},
		AllGroups: true, Endpoints: []UpdateEndpoint{{
			ID: "guard-one", Name: "Guard One", Protocol: "openai_compatible",
			BaseURL: "http://127.0.0.1:18080", Model: "", Token: token,
			TimeoutMS: 1000, InputLimit: 1024, Enabled: true,
		}},
	}
}
