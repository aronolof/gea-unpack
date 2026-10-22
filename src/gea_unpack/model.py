from dataclasses import dataclass, field


@dataclass
class ArchiveReport:
    sources: list[dict]
    header: dict
    members: list[dict]
    operation: str
    verified: bool = False
    outputs: list[dict] = field(default_factory=list)
    trailer: dict | None = None

    def to_dict(self):
        from dataclasses import asdict

        return {"schema_version": "2.0.0", **asdict(self)}
