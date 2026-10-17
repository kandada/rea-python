"""Pure, side-effect-free domain layer.

Rule: modules here must never import from ``providers``, ``application``, ``cli``,
``server`` or ``process``. Dependencies only flow inward.
"""
