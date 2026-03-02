"""Support for tracking an Audi."""

from __future__ import annotations

from typing import Any

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AudiRuntimeData
from .audi_entity import AudiEntity
from .coordinator import AudiDataUpdateCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime_data: AudiRuntimeData = config_entry.runtime_data
    entities: list[TrackerEntity] = []
    for config_vehicle in runtime_data.account.config_vehicles:
        vehicle = config_vehicle.vehicle
        if vehicle.state.get("position"):
            entities.append(AudiDeviceTracker(runtime_data.coordinator, vehicle))
    async_add_entities(entities)


class AudiDeviceTracker(AudiEntity, TrackerEntity):
    """Representation of an Audi device tracker."""

    _attr_icon = "mdi:car"
    _attr_name = "Position"
    _attr_should_poll = False
    _attr_source_type = SourceType.GPS

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator, vehicle)
        self._attr_unique_id = (
            f"{vehicle.vin.lower()}_device_tracker_position"
        )

    def _position(self) -> dict[str, Any]:
        """Return the position dict from vehicle state, or empty dict."""
        return self._vehicle.state.get("position") or {}

    @property
    def latitude(self) -> float | None:
        pos = self._position()
        val = pos.get("latitude")
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                return None
        return None

    @property
    def longitude(self) -> float | None:
        pos = self._position()
        val = pos.get("longitude")
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                return None
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = {
            "model": f"{self._vehicle.model or 'Unknown'}/{self._vehicle.title}",
            "model_year": getattr(self._vehicle, "model_year", None),
            "model_family": getattr(self._vehicle, "model_family", None),
            "csid": getattr(self._vehicle, "csid", None),
            "vin": getattr(self._vehicle, "vin", None),
        }
        return {k: v for k, v in attrs.items() if v is not None}


__all__ = ["AudiDeviceTracker", "async_setup_entry"]
