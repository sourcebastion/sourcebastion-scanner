"""Built-in canonical source adapters sharing one reader and discovery."""

from .compose_requirements import _compose


def compose_source(source, *, source_sha256, producer, environment=None, config=None, limits=None):
    """Compose requirements, static Python manifests and registry lock evidence."""
    return _compose(
        source,
        source_sha256=source_sha256,
        producer=producer,
        environment=environment,
        config=config,
        limits=limits,
        manifest_inputs=True,
    )
