"""Base entity for Audi Connect."""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AudiDataUpdateCoordinator

# ---------------------------------------------------------------------------
# Shared field-key tuples used by both sensor.py and lock.py
# ---------------------------------------------------------------------------
_DOOR_OPEN_KEYS = (
    "OPEN_STATE_LEFT_FRONT_DOOR",
    "OPEN_STATE_LEFT_REAR_DOOR",
    "OPEN_STATE_RIGHT_FRONT_DOOR",
    "OPEN_STATE_RIGHT_REAR_DOOR",
)
_DOOR_LOCK_KEYS = (
    "LOCK_STATE_LEFT_FRONT_DOOR",
    "LOCK_STATE_LEFT_REAR_DOOR",
    "LOCK_STATE_RIGHT_FRONT_DOOR",
    "LOCK_STATE_RIGHT_REAR_DOOR",
)


def compute_doors_trunk_status(vehicle: Any) -> str | None:
    """Compute aggregate doors/trunk status from vehicle fields.

    Returns "Open", "Closed", "Locked", or None if data is missing.
    """
    fields = vehicle.fields
    door_open_vals = [fields.get(k) for k in _DOOR_OPEN_KEYS]
    door_lock_vals = [fields.get(k) for k in _DOOR_LOCK_KEYS]
    trunk_open = fields.get("OPEN_STATE_TRUNK_LID")
    trunk_lock = fields.get("LOCK_STATE_TRUNK_LID")

    if (
        not all(v is not None for v in door_open_vals)
        or not all(v is not None for v in door_lock_vals)
        or trunk_open is None
        or trunk_lock is None
    ):
        return None

    if any(v != "3" for v in door_open_vals) or trunk_open != "3":
        return "Open"
    if any(v != "2" for v in door_lock_vals) or trunk_lock != "2":
        return "Closed"
    return "Locked"


class AudiEntity(CoordinatorEntity[AudiDataUpdateCoordinator]):
    """Base class for all Audi entities."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator)
        self._vehicle = vehicle

    @property
    def device_info(self) -> DeviceInfo:
        model_info = (self._vehicle.model or "Unknown").replace("Audi ", "")
        return DeviceInfo(
            identifiers={(DOMAIN, self._vehicle.vin.lower())},
            manufacturer="Audi",
            name=self._vehicle.title,
            model=f"{model_info} ({self._vehicle.model_year})",
        )


__all__ = ["AudiEntity", "compute_doors_trunk_status"]
