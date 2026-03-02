"""Support for Audi Connect switches."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AudiRuntimeData
from .audi_entity import AudiEntity
from .coordinator import AudiDataUpdateCoordinator


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _preheater_active(vehicle: Any) -> bool:
    """Return True if preheater climatisation state is not 'off'."""
    ps = vehicle.state.get("preheaterState")
    if not isinstance(ps, dict):
        return False
    report = ps.get("climatisationStateReport")
    if not isinstance(report, dict):
        return False
    return report.get("climatisationState") != "off"


# ---------------------------------------------------------------------------
# Description dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class AudiSwitchEntityDescription(SwitchEntityDescription):
    """Describes an Audi switch entity."""

    value_fn: Callable[[Any], bool]
    supported_fn: Callable[[Any], bool]
    turn_on_fn: Callable[[Any, str], Coroutine[Any, Any, None]]
    turn_off_fn: Callable[[Any, str], Coroutine[Any, Any, None]]


SWITCH_DESCRIPTIONS: tuple[AudiSwitchEntityDescription, ...] = (
    AudiSwitchEntityDescription(
        key="preheater_active",
        name="Preheater",
        icon="mdi:radiator",
        value_fn=_preheater_active,
        supported_fn=lambda v: v.state.get("preheaterState") is not None,
        turn_on_fn=lambda conn, vin: conn.set_vehicle_pre_heater(vin, True),
        turn_off_fn=lambda conn, vin: conn.set_vehicle_pre_heater(vin, False),
    ),
)


# ---------------------------------------------------------------------------
# Platform setup
# ---------------------------------------------------------------------------


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime_data: AudiRuntimeData = config_entry.runtime_data
    entities: list[SwitchEntity] = []
    for config_vehicle in runtime_data.account.config_vehicles:
        vehicle = config_vehicle.vehicle
        for description in SWITCH_DESCRIPTIONS:
            if description.supported_fn(vehicle):
                entities.append(
                    AudiSwitch(runtime_data.coordinator, description, vehicle)
                )
    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Entity class
# ---------------------------------------------------------------------------


class AudiSwitch(AudiEntity, SwitchEntity):
    """Representation of an Audi switch."""

    entity_description: AudiSwitchEntityDescription

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        description: AudiSwitchEntityDescription,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator, vehicle)
        self.entity_description = description
        self._attr_unique_id = (
            f"{vehicle.vin.lower()}_switch_{description.key}"
        )

    @property
    def is_on(self) -> bool:
        return self.entity_description.value_fn(self._vehicle)

    async def async_turn_on(self, **kwargs: Any) -> None:
        connection = self.coordinator.account.connection
        await self.entity_description.turn_on_fn(
            connection, self._vehicle.vin
        )
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        connection = self.coordinator.account.connection
        await self.entity_description.turn_off_fn(
            connection, self._vehicle.vin
        )
        await self.coordinator.async_request_refresh()


__all__ = ["AudiSwitch", "async_setup_entry"]
