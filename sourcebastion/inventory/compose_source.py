"""Built-in canonical source adapters sharing one reader and discovery."""

from .compose_requirements import _compose


def compose_source(
    source, *, source_sha256, producer, environment=None, config=None, limits=None, go_runtime=None, budget=None
):
    """Compose static Python and npm declarations and source lock evidence."""
    return _compose(
        source,
        source_sha256=source_sha256,
        producer=producer,
        environment=environment,
        config=config,
        limits=limits,
        manifest_inputs=True,
        go_runtime=go_runtime,
        budget=budget,
    )
