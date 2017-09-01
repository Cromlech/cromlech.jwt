# -*- coding: utf-8 -*-


def list_tales():
    """Tales registry
    """
    from pkg_resources import iter_entry_points
    extra_tales = {}
    for ept in iter_entry_points(group='chameleon.tales'):
        if ept.name in extra_tales:
            raise KeyError(
                'TALES name %r is defined more than once' % ept.name)
        extra_tales[ept.name] = ept.load()
    return extra_tales

extra_tales = list_tales()

# Exposing public API
from dolmen.template.components import Template, TALTemplate

__all__ = ['Template', 'TALTemplate', 'extra_tales']
