"""FishPoker HTTP+TCP API integration.

This package provides a FishPokerAPI that matches Worker expectations.
"""

from .api import FishPokerAPI, ApiError

__all__ = ["FishPokerAPI", "ApiError"]
