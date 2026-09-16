package provider

import (
	"context"
	"encoding/json"
	"net/http"
)

func (c *Client) GetUsageEvidence(ctx context.Context, descriptor ReadDescriptor, admission Admission) (UsageEvidence, error) {
	path := "/v1/operations/" + descriptor.OperationID + "/usage-evidence"
	if descriptor.Operation != "read_usage_evidence" || validateReadAdmission(descriptor, admission, UsageDescriptorContractID, path) != nil {
		return UsageEvidence{}, ErrAdmissionBinding
	}
	request, err := c.newRequest(ctx, http.MethodGet, path, nil, &admission)
	if err != nil {
		return UsageEvidence{}, err
	}
	response, err := c.do(request, http.StatusOK, statusSet(400, 401, 403, 404, 410, 503))
	if err != nil {
		return UsageEvidence{}, err
	}
	var result UsageEvidence
	if err := decodeUsageEvidence(response, &result); err != nil {
		return UsageEvidence{}, err
	}
	if result.OperationID != descriptor.OperationID || result.AttemptID != descriptor.AttemptID || result.FencingToken != descriptor.FencingToken || result.SandboxID != descriptor.SandboxID {
		return UsageEvidence{}, ErrInvalidContractDocument
	}
	return result, nil
}

func decodeUsageEvidence(document []byte, target *UsageEvidence) error {
	object, err := decodeStrict(document, target,
		[]string{"evidence_id", "sandbox_id", "operation_id", "attempt_id", "fencing_token", "entries", "reconciliation_status", "observed_at", "retained_until", "evidence_digest"}, nil)
	if err != nil {
		return err
	}
	if !arrayObjectShape(object["entries"], []string{"entry_id", "sandbox_id", "meter", "quantity", "unit", "meter_source", "evidence_reference", "occurred_at"}, []string{"operation_id"}) {
		return ErrInvalidContractDocument
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(object["entries"], &entries) != nil {
		return ErrInvalidContractDocument
	}
	for i, entry := range entries {
		if _, present := entry["operation_id"]; present && target.Entries[i].OperationID == "" {
			return ErrInvalidContractDocument
		}
	}
	return validateUsageEvidence(*target)
}

func validateUsageEvidence(value UsageEvidence) error {
	if !identifierPattern.MatchString(value.EvidenceID) || !identifierPattern.MatchString(value.SandboxID) || !identifierPattern.MatchString(value.OperationID) || !identifierPattern.MatchString(value.AttemptID) || value.FencingToken < 1 || value.FencingToken > maxSafeInteger || len(value.Entries) < 1 || len(value.Entries) > 16 || !oneOf(value.ReconciliationStatus, "complete", "partial", "unknown") || !validDateTime(value.ObservedAt) || !validDateTime(value.RetainedUntil) || !digestPattern.MatchString(value.EvidenceDigest) {
		return ErrInvalidContractDocument
	}
	units := map[string]string{
		"sandbox.wall_time_milliseconds": "milliseconds", "sandbox.cpu_nanoseconds": "nanoseconds",
		"sandbox.memory_byte_milliseconds": "byte-milliseconds", "sandbox.network_ingress_bytes": "bytes",
		"sandbox.network_egress_bytes": "bytes", "sandbox.storage_read_bytes": "bytes", "sandbox.storage_write_bytes": "bytes",
		"sandbox.workspace_peak_bytes": "bytes", "sandbox.exec_count": "count", "sandbox.browser_session_milliseconds": "milliseconds",
	}
	seen := make(map[string]bool)
	for _, entry := range value.Entries {
		unit, known := units[entry.Meter]
		if !identifierPattern.MatchString(entry.EntryID) || seen[entry.EntryID] || entry.SandboxID != value.SandboxID || entry.OperationID != "" && entry.OperationID != value.OperationID || !known || entry.Unit != unit || entry.Quantity < 0 || entry.Quantity > maxSafeInteger || !oneOf(entry.MeterSource, "platform_metered", "runtime_metered", "reconciled") || !opaqueReference(entry.EvidenceReference, "ref:") || !validDateTime(entry.OccurredAt) {
			return ErrInvalidContractDocument
		}
		seen[entry.EntryID] = true
	}
	return nil
}
