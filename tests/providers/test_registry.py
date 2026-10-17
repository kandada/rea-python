import pytest

from rea_mcp.domain.analysis_profile import ProviderIdentity
from rea_mcp.domain.binary_target import BinaryTarget
from rea_mcp.providers.base import AnalysisProvider, CapabilityDescriptor
from rea_mcp.providers.registry import AnalysisProviderRegistry


class _Provider(AnalysisProvider):
    def __init__(self, provider_id: str, formats: set[str], operations: tuple[str, ...]) -> None:
        self._id = provider_id
        self._formats = formats
        self._operations = operations

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(id=self._id, name=self._id.upper(), version="1")

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(
            CapabilityDescriptor(operation=op, provider=self.identity()) for op in self._operations
        )

    def supports(self, target: BinaryTarget):  # type: ignore[no-untyped-def]
        from rea_mcp.providers.registry import TargetSupport

        return TargetSupport("supported" if target.format in self._formats else "unsupported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        raise NotImplementedError


def _target(fmt: str) -> BinaryTarget:
    return BinaryTarget(path=f"/tmp/x.{fmt}", sha256="a" * 64, format=fmt)  # type: ignore[arg-type]


def test_identities_are_sorted_regardless_of_registration() -> None:
    a = _Provider("zeta", {"elf"}, ("op_a",))
    b = _Provider("alpha", {"elf"}, ("op_b",))
    registry = AnalysisProviderRegistry([a, b])
    assert registry.identities() == ["alpha", "zeta"]


def test_duplicate_ids_are_rejected() -> None:
    a = _Provider("dup", {"elf"}, ("op_a",))
    b = _Provider("dup", {"elf"}, ("op_b",))
    with pytest.raises(TypeError):
        AnalysisProviderRegistry([a, b])


def test_applicable_returns_all_supporting_providers() -> None:
    a = _Provider("alpha", {"elf"}, ("op_a",))
    b = _Provider("beta", {"elf"}, ("op_b",))
    c = _Provider("gamma", {"pe"}, ("op_c",))
    registry = AnalysisProviderRegistry([a, b, c])
    result = registry.applicable_providers(_target("elf"))
    assert result.ok
    assert [provider.identity().id for provider in result.value] == ["alpha", "beta"]


def test_explicit_provider_binding() -> None:
    a = _Provider("alpha", {"elf"}, ("op_a",))
    b = _Provider("beta", {"elf"}, ("op_b",))
    registry = AnalysisProviderRegistry([a, b])
    result = registry.applicable_providers(_target("elf"), "beta")
    assert result.ok
    assert [provider.identity().id for provider in result.value] == ["beta"]


def test_unknown_provider_is_rejected() -> None:
    registry = AnalysisProviderRegistry([_Provider("alpha", {"elf"}, ("op_a",))])
    result = registry.applicable_providers(_target("elf"), "missing")
    assert not result.ok
    assert result.error.tag == "ProviderSelectionError"
    assert "unknown_provider" in result.error.message  # type: ignore[attr-defined]


def test_unsupported_target_for_explicit_provider() -> None:
    registry = AnalysisProviderRegistry([_Provider("alpha", {"elf"}, ("op_a",))])
    result = registry.applicable_providers(_target("pe"), "alpha")
    assert not result.ok


def test_no_supporting_provider_reports_target_unsupported() -> None:
    registry = AnalysisProviderRegistry([_Provider("alpha", {"elf"}, ("op_a",))])
    result = registry.applicable_providers(_target("sqlite"))
    assert not result.ok
