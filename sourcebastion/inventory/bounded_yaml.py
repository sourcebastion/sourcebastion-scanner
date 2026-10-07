"""Data-only multi-document YAML with admission before object construction."""

import yaml
from yaml.events import (
    AliasEvent,
    DocumentStartEvent,
    MappingStartEvent,
    MappingEndEvent,
    SequenceStartEvent,
    SequenceEndEvent,
    ScalarEvent,
)

from .inputs import InputRefusal


def load_documents(content, *, check):
    if type(content) is not bytes or not callable(check):
        raise TypeError("trusted-yaml-bytes-and-check-required")
    if len(content) > 2 * 1024 * 1024:
        raise InputRefusal("input-file-budget-exceeded")
    try:
        text = content.decode("utf-8-sig")
        depth = nodes = documents = 0
        for event in yaml.parse(text, Loader=yaml.BaseLoader):
            check()
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
                raise InputRefusal("unsupported-yaml-alias-or-anchor")
            if getattr(event, "tag", None) is not None:
                raise InputRefusal("unsupported-yaml-tag")
            if isinstance(event, ScalarEvent) and any(0xD800 <= ord(char) <= 0xDFFF for char in event.value):
                raise InputRefusal("invalid-yaml-unicode")
            if isinstance(event, DocumentStartEvent):
                documents += 1
                if documents > 32:
                    raise InputRefusal("yaml-document-budget-exceeded")
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
                if depth > 32:
                    raise InputRefusal("yaml-depth-budget-exceeded")
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                depth -= 1
            if isinstance(event, (MappingStartEvent, SequenceStartEvent, ScalarEvent)):
                nodes += 1
                if nodes > 2000000:
                    raise InputRefusal("yaml-node-budget-exceeded")

        class Loader(yaml.BaseLoader):
            def construct_mapping(self, node, deep=False):
                check()
                if not isinstance(node, yaml.MappingNode):
                    raise InputRefusal("invalid-yaml-mapping")
                result = {}
                for key_node, value_node in node.value:
                    check()
                    if not isinstance(key_node, yaml.ScalarNode):
                        raise InputRefusal("unsupported-yaml-map-key")
                    key = self.construct_scalar(key_node)
                    if key == "<<" or key in result:
                        raise InputRefusal("duplicate-or-merged-yaml-key")
                    result[key] = self.construct_object(value_node, deep=deep)
                return result

            def construct_scalar(self, node):
                check()
                return super().construct_scalar(node)

            def construct_sequence(self, node, deep=False):
                check()
                return super().construct_sequence(node, deep=deep)

        result = tuple(yaml.load_all(text, Loader=Loader))
        check()
        if not result or any(type(value) is not dict for value in result):
            raise InputRefusal("invalid-yaml-document")
        return result
    except InputRefusal:
        raise
    except (yaml.YAMLError, UnicodeError, ValueError, RecursionError):
        raise InputRefusal("invalid-yaml-syntax") from None
