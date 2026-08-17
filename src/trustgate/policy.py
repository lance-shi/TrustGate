"""Pure, default-deny data-release policy evaluation."""

from __future__ import annotations

from .models import DataReleaseDecision, DataReleaseRequest, DataReleaseResult, TrustPolicy


def decide_data_release(
    policy: TrustPolicy | None,
    request: DataReleaseRequest,
) -> DataReleaseResult:
    """Return the explicit destination-aware release decision for one entity type.

    A missing policy, unknown entity type, and unknown destination all deny by
    default. This function only evaluates data-release policy; it does not
    authorize tool execution or access raw token-vault values.
    """
    decision = DataReleaseDecision.DENY
    if policy is not None:
        data_policy = policy.data_policies.get(request.entity_type)
        if data_policy is not None:
            decision = data_policy.destinations.get(request.destination, decision)
    return DataReleaseResult(
        entity_type=request.entity_type,
        destination=request.destination,
        decision=decision,
    )
