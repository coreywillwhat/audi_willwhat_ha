"""Support for Audi Connect locks."""

from __future__ import annotations

from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AudiRuntimeData
from .audi_entity import AudiEntity, compute_doors_trunk_status
from .coordinator import AudiDataUpdateCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime_data: AudiRuntimeData = config_entry.runtime_data
    entities: list[LockEntity] = []
    for config_vehicle in runtime_data.account.config_vehicles:
        vehicle = config_vehicle.vehicle
        # Lock requires door/trunk field data AND a SPIN PIN to be configured.
        if (
            compute_doors_trunk_status(vehicle) is not None
            and runtime_data.account.connection._audi_service._spin is not None
        ):
            entities.append(AudiLock(runtime_data.coordinator, vehicle))
    async_add_entities(entities)


class AudiLock(AudiEntity, LockEntity):
    """Representation of an Audi lock."""

    _attr_name = "Door lock"

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator, vehicle)
        self._attr_unique_id = f"{vehicle.vin.lower()}_lock_lock"

    @property
    def is_locked(self) -> bool:
        return compute_doors_trunk_status(self._vehicle) == "Locked"

    async def async_lock(self, **kwargs: Any) -> None:
        connection = self.coordinator.account.connection
        await connection.set_vehicle_lock(self._vehicle.vin, True)
        await self.coordinator.async_request_refresh()

    async def async_unlock(self, **kwargs: Any) -> None:
        connection = self.coordinator.account.connection
        await connection.set_vehicle_lock(self._vehicle.vin, False)
        await self.coordinator.async_request_refresh()


__all__ = ["AudiLock", "async_setup_entry"]
