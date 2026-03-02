"""Support for Audi Connect binary sensors."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AudiRuntimeData
from .audi_entity import AudiEntity
from .coordinator import AudiDataUpdateCoordinator


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _field_ne(fields: dict[str, Any], key: str, closed_val: str) -> bool | None:
    """Return True if field exists and != closed_val, None if missing."""
    val = fields.get(key)
    return val != closed_val if val is not None else None


# ── Aggregate: any window open ──────────────────────────────────────────

_WINDOW_KEYS = (
    "STATE_LEFT_FRONT_WINDOW",
    "STATE_LEFT_REAR_WINDOW",
    "STATE_RIGHT_FRONT_WINDOW",
    "STATE_RIGHT_REAR_WINDOW",
)
_WINDOW_EXTRA_KEYS = ("STATE_SUN_ROOF_MOTOR_COVER", "STATE_ROOF_COVER_WINDOW")
_ACCEPTABLE_EXTRA_STATES = ("3", "0")


def _any_window_open_supported(vehicle: Any) -> bool:
    fields = vehicle.fields
    if not all(fields.get(k) for k in _WINDOW_KEYS):
        return False
    for k in _WINDOW_EXTRA_KEYS:
        v = fields.get(k)
        if v is not None and v not in _ACCEPTABLE_EXTRA_STATES:
            return False
    return True


def _any_window_open(vehicle: Any) -> bool | None:
    if not _any_window_open_supported(vehicle):
        return None
    fields = vehicle.fields
    for k in _WINDOW_EXTRA_KEYS:
        v = fields.get(k)
        if v is not None and v != "3":
            return True
    return any(fields.get(k) != "3" for k in _WINDOW_KEYS)


# ── Aggregate: any door unlocked ────────────────────────────────────────

_DOOR_LOCK_KEYS = (
    "LOCK_STATE_LEFT_FRONT_DOOR",
    "LOCK_STATE_LEFT_REAR_DOOR",
    "LOCK_STATE_RIGHT_FRONT_DOOR",
    "LOCK_STATE_RIGHT_REAR_DOOR",
)


def _any_door_unlocked_supported(vehicle: Any) -> bool:
    fields = vehicle.fields
    return all(fields.get(k) for k in _DOOR_LOCK_KEYS)


def _any_door_unlocked(vehicle: Any) -> bool | None:
    if not _any_door_unlocked_supported(vehicle):
        return None
    fields = vehicle.fields
    return any(fields.get(k) != "2" for k in _DOOR_LOCK_KEYS)


# ── Aggregate: any door open ────────────────────────────────────────────

_DOOR_OPEN_KEYS = (
    "OPEN_STATE_LEFT_FRONT_DOOR",
    "OPEN_STATE_LEFT_REAR_DOOR",
    "OPEN_STATE_RIGHT_FRONT_DOOR",
    "OPEN_STATE_RIGHT_REAR_DOOR",
)


def _any_door_open_supported(vehicle: Any) -> bool:
    fields = vehicle.fields
    return all(fields.get(k) for k in _DOOR_OPEN_KEYS)


def _any_door_open(vehicle: Any) -> bool | None:
    if not _any_door_open_supported(vehicle):
        return None
    fields = vehicle.fields
    return any(fields.get(k) != "3" for k in _DOOR_OPEN_KEYS)


# ── Parking light ───────────────────────────────────────────────────────

def _parking_light(vehicle: Any) -> bool | None:
    lights = vehicle.fields.get("LIGHT_STATUS")
    if not lights:
        return None
    try:
        return lights[0]["status"] != "off" or lights[1]["status"] != "off"
    except (KeyError, IndexError, TypeError):
        return False


# ── Oil level binary ────────────────────────────────────────────────────

def _oil_level_binary(vehicle: Any) -> bool | None:
    val = vehicle.fields.get("OIL_LEVEL_DIPSTICKS_PERCENTAGE")
    if not isinstance(val, bool):
        return None
    return not val


# ---------------------------------------------------------------------------
# Description dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class AudiBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes an Audi binary sensor entity."""

    value_fn: Callable[[Any], bool | None]
    supported_fn: Callable[[Any], bool] | None = None


# ---------------------------------------------------------------------------
# Binary sensor descriptions
# ---------------------------------------------------------------------------

BINARY_SENSOR_DESCRIPTIONS: tuple[AudiBinarySensorEntityDescription, ...] = (
    # ── Charging plug ───────────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="plug_state",
        name="Plug state",
        icon="mdi:ev-plug-type1",
        device_class=BinarySensorDeviceClass.PLUG,
        value_fn=lambda v: v.state.get("plugState") != "disconnected"
        if v.state.get("plugState") is not None
        else None,
    ),
    AudiBinarySensorEntityDescription(
        key="plug_lock_state",
        name="Plug Lock state",
        icon="mdi:ev-plug-type1",
        device_class=BinarySensorDeviceClass.LOCK,
        value_fn=lambda v: v.state.get("plugLockState") != "locked"
        if v.state.get("plugLockState") is not None
        else None,
    ),
    # ── Climate / heating ───────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="glass_surface_heating",
        name="Glass Surface Heating",
        icon="mdi:car-defrost-front",
        device_class=BinarySensorDeviceClass.RUNNING,
        value_fn=lambda v: v.state.get("isMirrorHeatingActive"),
    ),
    # ── Roof ────────────────────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="sun_roof",
        name="Sun roof",
        device_class=BinarySensorDeviceClass.WINDOW,
        value_fn=lambda v: _field_ne(v.fields, "STATE_SUN_ROOF_MOTOR_COVER", "3"),
        supported_fn=lambda v: "STATE_SUN_ROOF_MOTOR_COVER" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="roof_cover",
        name="Roof Cover",
        device_class=BinarySensorDeviceClass.WINDOW,
        value_fn=lambda v: _field_ne(v.fields, "STATE_ROOF_COVER_WINDOW", "3"),
        supported_fn=lambda v: "STATE_ROOF_COVER_WINDOW" in v.fields,
    ),
    # ── Parking light / safety ──────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="parking_light",
        name="Parking light",
        device_class=BinarySensorDeviceClass.SAFETY,
        icon="mdi:lightbulb",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_parking_light,
        supported_fn=lambda v: bool(v.fields.get("LIGHT_STATUS")),
    ),
    # ── Aggregate windows / doors ───────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="any_window_open",
        name="Windows",
        device_class=BinarySensorDeviceClass.WINDOW,
        value_fn=_any_window_open,
        supported_fn=_any_window_open_supported,
    ),
    AudiBinarySensorEntityDescription(
        key="any_door_unlocked",
        name="Doors lock",
        device_class=BinarySensorDeviceClass.LOCK,
        value_fn=_any_door_unlocked,
        supported_fn=_any_door_unlocked_supported,
    ),
    AudiBinarySensorEntityDescription(
        key="any_door_open",
        name="Doors",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_any_door_open,
        supported_fn=_any_door_open_supported,
    ),
    # ── Trunk ───────────────────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="trunk_unlocked",
        name="Trunk lock",
        device_class=BinarySensorDeviceClass.LOCK,
        value_fn=lambda v: _field_ne(v.fields, "LOCK_STATE_TRUNK_LID", "2"),
        supported_fn=lambda v: "LOCK_STATE_TRUNK_LID" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="trunk_open",
        name="Trunk",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda v: _field_ne(v.fields, "OPEN_STATE_TRUNK_LID", "3"),
        supported_fn=lambda v: "OPEN_STATE_TRUNK_LID" in v.fields,
    ),
    # ── Hood ────────────────────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="hood_open",
        name="Hood",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda v: _field_ne(v.fields, "OPEN_STATE_HOOD", "3"),
        supported_fn=lambda v: "OPEN_STATE_HOOD" in v.fields,
    ),
    # ── Individual doors ────────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="left_front_door_open",
        name="Left front door",
        device_class=BinarySensorDeviceClass.DOOR,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "OPEN_STATE_LEFT_FRONT_DOOR", "3"),
        supported_fn=lambda v: "OPEN_STATE_LEFT_FRONT_DOOR" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="right_front_door_open",
        name="Right front door",
        device_class=BinarySensorDeviceClass.DOOR,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "OPEN_STATE_RIGHT_FRONT_DOOR", "3"),
        supported_fn=lambda v: "OPEN_STATE_RIGHT_FRONT_DOOR" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="left_rear_door_open",
        name="Left rear door",
        device_class=BinarySensorDeviceClass.DOOR,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "OPEN_STATE_LEFT_REAR_DOOR", "3"),
        supported_fn=lambda v: "OPEN_STATE_LEFT_REAR_DOOR" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="right_rear_door_open",
        name="Right rear door",
        device_class=BinarySensorDeviceClass.DOOR,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "OPEN_STATE_RIGHT_REAR_DOOR", "3"),
        supported_fn=lambda v: "OPEN_STATE_RIGHT_REAR_DOOR" in v.fields,
    ),
    # ── Individual windows ──────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="left_front_window_open",
        name="Left front window",
        device_class=BinarySensorDeviceClass.WINDOW,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "STATE_LEFT_FRONT_WINDOW", "3"),
        supported_fn=lambda v: "STATE_LEFT_FRONT_WINDOW" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="right_front_window_open",
        name="Right front window",
        device_class=BinarySensorDeviceClass.WINDOW,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "STATE_RIGHT_FRONT_WINDOW", "3"),
        supported_fn=lambda v: "STATE_RIGHT_FRONT_WINDOW" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="left_rear_window_open",
        name="Left rear window",
        device_class=BinarySensorDeviceClass.WINDOW,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "STATE_LEFT_REAR_WINDOW", "3"),
        supported_fn=lambda v: "STATE_LEFT_REAR_WINDOW" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="right_rear_window_open",
        name="Right rear window",
        device_class=BinarySensorDeviceClass.WINDOW,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _field_ne(v.fields, "STATE_RIGHT_REAR_WINDOW", "3"),
        supported_fn=lambda v: "STATE_RIGHT_REAR_WINDOW" in v.fields,
    ),
    # ── Safety / diagnostics ────────────────────────────────────────────
    AudiBinarySensorEntityDescription(
        key="braking_status",
        name="Braking status",
        device_class=BinarySensorDeviceClass.SAFETY,
        icon="mdi:car-brake-abs",
        value_fn=lambda v: _field_ne(v.fields, "BRAKING_STATUS", "2"),
        supported_fn=lambda v: "BRAKING_STATUS" in v.fields,
    ),
    AudiBinarySensorEntityDescription(
        key="oil_level_binary",
        name="Oil Level Binary",
        icon="mdi:oil",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_oil_level_binary,
        supported_fn=lambda v: isinstance(
            v.fields.get("OIL_LEVEL_DIPSTICKS_PERCENTAGE"), bool
        ),
    ),
    AudiBinarySensorEntityDescription(
        key="is_moving",
        name="Is moving",
        icon="mdi:motion-outline",
        device_class=BinarySensorDeviceClass.MOVING,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: v.state.get("is_moving"),
        supported_fn=lambda v: True,
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
    entities: list[BinarySensorEntity] = []

    for config_vehicle in runtime_data.account.config_vehicles:
        vehicle = config_vehicle.vehicle
        for description in BINARY_SENSOR_DESCRIPTIONS:
            if description.supported_fn is not None:
                supported = description.supported_fn(vehicle)
            else:
                supported = description.value_fn(vehicle) is not None
            if supported:
                entities.append(
                    AudiBinarySensor(runtime_data.coordinator, description, vehicle)
                )

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Entity class
# ---------------------------------------------------------------------------


class AudiBinarySensor(AudiEntity, BinarySensorEntity):
    """Representation of an Audi binary sensor."""

    entity_description: AudiBinarySensorEntityDescription

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        description: AudiBinarySensorEntityDescription,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator, vehicle)
        self.entity_description = description
        self._attr_unique_id = (
            f"{vehicle.vin.lower()}_binary_sensor_{description.key}"
        )

    @property
    def is_on(self) -> bool | None:
        return self.entity_description.value_fn(self._vehicle)


__all__ = ["AudiBinarySensor", "async_setup_entry"]
