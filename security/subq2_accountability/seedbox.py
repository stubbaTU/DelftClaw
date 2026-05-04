from dataclasses import dataclass, field
from datetime import datetime

from security.contracts import SeedboxDonationEvidence


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

    def to_evidence(self) -> SeedboxDonationEvidence:
        return SeedboxDonationEvidence(
            donation_id=self.donation_id,
            seedbox_id=self.seedbox_id,
            donor_id=self.donor_id,
            recipient_id=self.recipient_id,
            amount_sats=self.amount_sats,
            txid=self.txid,
            self_donation=self.self_donation,
            fake_seedbox=self.fake_seedbox,
            stolen_from_honest_agent=self.stolen_from_honest_agent,
        )


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
