"""
LEGACY
"""
from dataclasses import dataclass, field, replace
from datetime import datetime
from random import choice

from security.contracts import AtomicMicrotaskEvidence, SeedboxDonationEvidence
from security.accountability_layer.infrastructure.bitcoin_anchor import BitcoinAnchor


@dataclass(frozen=True)
class Seedbox:
    seedbox_id: str
    owner_id: str
    donation_address: str
    advertised_capacity_gb: int
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    fake: bool = False


@dataclass(frozen=True)
class Donation:
    donation_id: str
    seedbox_id: str
    donor_id: str
    recipient_id: str
    amount_sats: int
    txid: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    self_donation: bool = False
    fake_seedbox: bool = False
    stolen_from_honest_agent: bool = False
    bitcoin_anchor: BitcoinAnchor | None = None

    def to_evidence(self) -> SeedboxDonationEvidence:
        return SeedboxDonationEvidence(
            donation_id=self.donation_id,
            seedbox_id=self.seedbox_id,
            donor_id=self.donor_id,
            recipient_id=self.recipient_id,
            amount_sats=self.amount_sats,
            txid=self.txid,
            bitcoin_anchor=self.bitcoin_anchor.to_dict() if self.bitcoin_anchor else {},
            self_donation=self.self_donation,
            fake_seedbox=self.fake_seedbox,
            stolen_from_honest_agent=self.stolen_from_honest_agent,
        )


@dataclass(frozen=True)
class ServiceProof:
    proof_id: str
    seedbox_id: str
    prover_id: str
    storage_url: str
    nonce: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass(frozen=True)
class AtomicMicrotask:
    task_id: str
    seedbox_id: str
    prover_id: str
    task_type: str
    file_hash: str
    result_hash: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    verified: bool = False

    def to_evidence(self) -> AtomicMicrotaskEvidence:
        return AtomicMicrotaskEvidence(
            task_id=self.task_id,
            seedbox_id=self.seedbox_id,
            prover_id=self.prover_id,
            task_type=self.task_type,
            file_hash=self.file_hash,
            result_hash=self.result_hash,
            verified=self.verified,
        )


@dataclass(frozen=True)
class IndexedFile:
    file_id: str
    seedbox_id: str
    name: str
    content_url: str
    sha256: str = ""
    size_bytes: int = 0
    media_type: str = ""
    tags: tuple[str, ...] = ()
    indexed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class SeedboxRegistry:
    def __init__(self):
        self.seedboxes: dict[str, Seedbox] = {}

    def register(
        self,
        seedbox_id: str,
        owner_id: str,
        donation_address: str,
        advertised_capacity_gb: int,
        fake: bool = False,
    ) -> Seedbox:
        seedbox = Seedbox(
            seedbox_id=seedbox_id,
            owner_id=owner_id,
            donation_address=donation_address,
            advertised_capacity_gb=advertised_capacity_gb,
            fake=fake,
        )
        self.seedboxes[seedbox_id] = seedbox
        return seedbox

    def get(self, seedbox_id: str) -> Seedbox:
        return self.seedboxes[seedbox_id]


class DonationLedger:
    def __init__(self, registry: SeedboxRegistry):
        self.registry = registry
        self.donations: list[Donation] = []

    def broadcast_donation(
        self,
        donation_id: str,
        seedbox_id: str,
        donor_id: str,
        amount_sats: int,
        txid: str,
        stolen_from_honest_agent: bool = False,
        bitcoin_anchor: BitcoinAnchor | None = None,
    ) -> Donation:
        seedbox = self.registry.get(seedbox_id)
        donation = Donation(
            donation_id=donation_id,
            seedbox_id=seedbox_id,
            donor_id=donor_id,
            recipient_id=seedbox.owner_id,
            amount_sats=amount_sats,
            txid=txid,
            self_donation=donor_id == seedbox.owner_id,
            fake_seedbox=seedbox.fake,
            stolen_from_honest_agent=stolen_from_honest_agent,
            bitcoin_anchor=bitcoin_anchor,
        )
        self.donations.append(donation)
        return donation

    def wash_trades_for(self, subject_id: str) -> list[Donation]:
        return [
            donation
            for donation in self.donations
            if donation.recipient_id == subject_id and donation.self_donation
        ]

    def fake_donations_for(self, subject_id: str) -> list[Donation]:
        return [
            donation
            for donation in self.donations
            if donation.recipient_id == subject_id and donation.fake_seedbox
        ]


class ServiceProofLedger:
    def __init__(self, registry: SeedboxRegistry):
        self.registry = registry
        self.proofs: list[ServiceProof] = []

    def submit_proof(
        self,
        proof_id: str,
        seedbox_id: str,
        prover_id: str,
        storage_url: str,
        nonce: str,
    ) -> ServiceProof:
        self.registry.get(seedbox_id)
        proof = ServiceProof(
            proof_id=proof_id,
            seedbox_id=seedbox_id,
            prover_id=prover_id,
            storage_url=storage_url,
            nonce=nonce,
        )
        self.proofs.append(proof)
        return proof

    def proofs_for_seedbox(self, seedbox_id: str) -> list[ServiceProof]:
        return [proof for proof in self.proofs if proof.seedbox_id == seedbox_id]


class AtomicMicrotaskLedger:
    def __init__(self, registry: SeedboxRegistry):
        self.registry = registry
        self.microtasks: list[AtomicMicrotask] = []

    def submit_result(
        self,
        task_id: str,
        seedbox_id: str,
        prover_id: str,
        task_type: str,
        file_hash: str,
        result_hash: str,
        verified: bool = False,
    ) -> AtomicMicrotask:
        self.registry.get(seedbox_id)
        microtask = AtomicMicrotask(
            task_id=task_id,
            seedbox_id=seedbox_id,
            prover_id=prover_id,
            task_type=task_type,
            file_hash=file_hash,
            result_hash=result_hash,
            verified=verified,
        )
        self.microtasks.append(microtask)
        return microtask

    def tasks_for_seedbox(self, seedbox_id: str) -> list[AtomicMicrotask]:
        return [task for task in self.microtasks if task.seedbox_id == seedbox_id]

    def get(self, task_id: str) -> AtomicMicrotask:
        for microtask in reversed(self.microtasks):
            if microtask.task_id == task_id:
                return microtask
        raise KeyError(task_id)

    def verify_result(self, task_id: str, expected_result_hash: str) -> AtomicMicrotask:
        microtask = self.get(task_id)
        if microtask.result_hash != expected_result_hash:
            raise ValueError(
                f"microtask {task_id} result_hash mismatch: "
                f"expected {expected_result_hash}, got {microtask.result_hash}"
            )
        verified = replace(microtask, verified=True)
        self.microtasks.append(verified)
        return verified


class SeedboxContentIndex:
    def __init__(self, registry: SeedboxRegistry):
        self.registry = registry
        self.files: list[IndexedFile] = []

    def index_file(
        self,
        *,
        file_id: str,
        seedbox_id: str,
        name: str,
        content_url: str,
        sha256: str = "",
        size_bytes: int = 0,
        media_type: str = "",
        tags: tuple[str, ...] = (),
    ) -> IndexedFile:
        self.registry.get(seedbox_id)
        indexed_file = IndexedFile(
            file_id=file_id,
            seedbox_id=seedbox_id,
            name=name,
            content_url=content_url,
            sha256=sha256,
            size_bytes=size_bytes,
            media_type=media_type,
            tags=tuple(tags),
        )
        self.files = [item for item in self.files if item.file_id != file_id]
        self.files.append(indexed_file)
        return indexed_file

    def list_files(self) -> list[IndexedFile]:
        return list(self.files)

    def search(self, query: str) -> list[IndexedFile]:
        normalized = query.casefold().strip()
        if not normalized:
            return self.list_files()
        return [
            item
            for item in self.files
            if normalized in item.name.casefold()
            or normalized in item.media_type.casefold()
            or any(normalized in tag.casefold() for tag in item.tags)
        ]

    def random_match(self, query: str = "") -> IndexedFile:
        matches = self.search(query)
        if not matches:
            raise KeyError(query or "no indexed files")
        return choice(matches)
