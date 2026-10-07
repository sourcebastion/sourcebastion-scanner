"""Built-in canonical source adapters sharing one reader and discovery."""

from .compose_requirements import _compose


def compose_source(source, *, source_sha256, producer, environment=None, config=None, limits=None):
    """Compose requirements and static Python manifests without execution."""
    return _compose(
        source,
        source_sha256=source_sha256,
        producer=producer,
        environment=environment,
        config=config,
        limits=limits,
        manifest_inputs=True,
    )
