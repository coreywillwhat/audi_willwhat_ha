"""Support for Audi Connect sensors."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfElectricCurrent,
    UnitOfLength,
    UnitOfPower,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AudiRuntimeData
from .audi_entity import AudiEntity, compute_doors_trunk_status
from .coordinator import AudiDataUpdateCoordinator
from .util import parse_datetime, parse_float, parse_int


# ---------------------------------------------------------------------------
# Helper functions for value extraction
# ---------------------------------------------------------------------------


def _filter_unsupported(val: Any) -> Any:
    """Return None for 'unsupported' or missing values."""
    return val if val is not None and val != "unsupported" else None


def _preheater_value(vehicle: Any, key: str) -> int | None:
    """Safely extract a value from the preheaterState nested dict."""
    ps = vehicle.state.get("preheaterState")
    if not isinstance(ps, dict):
        return None
    report = ps.get("climatisationStateReport")
    if not isinstance(report, dict):
        return None
    return parse_int(report.get(key))


def _external_power(vehicle: Any) -> str | None:
    """Map external power status to human-readable string."""
    val = vehicle.state.get("externalPower")
    if val is None:
        return None
    if val == "unavailable":
        return "Not Ready"
    if val == "ready":
        return "Ready"
    return val


def _trip_data_value(vehicle: Any, state_key: str) -> Any:
    """Extract timestamp from trip data dict as the sensor state."""
    td = vehicle.state.get(state_key)
    if td and isinstance(td, dict):
        return parse_datetime(td.get("timestamp"))
    return None


def _trip_data_attrs(vehicle: Any, state_key: str) -> dict[str, Any]:
    """Extract extra attributes from trip data dict."""
    td = vehicle.state.get(state_key)
    if not td or not isinstance(td, dict):
        return {}
    return {
        k: td.get(k)
        for k in (
            "averageElectricEngineConsumption",
            "averageFuelConsumption",
            "averageSpeed",
            "mileage",
            "overallMileage",
            "startMileage",
            "traveltime",
            "tripID",
            "zeroEmissionDistance",
        )
    }


# ---------------------------------------------------------------------------
# Description dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class AudiSensorEntityDescription(SensorEntityDescription):
    """Describes an Audi sensor entity."""

    value_fn: Callable[[Any], Any]
    supported_fn: Callable[[Any], bool] | None = None
    extra_attrs_fn: Callable[[Any], dict[str, Any]] | None = None


# ---------------------------------------------------------------------------
# Sensor descriptions
# ---------------------------------------------------------------------------

SENSOR_DESCRIPTIONS: tuple[AudiSensorEntityDescription, ...] = (
    # ── Timestamps / Trip data ──────────────────────────────────────────
    AudiSensorEntityDescription(
        key="last_update_time",
        name="Last Update",
        icon="mdi:update",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda v: v.state.get("last_update_time"),
    ),
    AudiSensorEntityDescription(
        key="shortterm_current",
        name="ShortTerm Trip Data",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda v: _trip_data_value(v, "shortterm_current"),
        extra_attrs_fn=lambda v: _trip_data_attrs(v, "shortterm_current"),
    ),
    AudiSensorEntityDescription(
        key="shortterm_reset",
        name="ShortTerm Trip User Reset",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda v: _trip_data_value(v, "shortterm_reset"),
        extra_attrs_fn=lambda v: _trip_data_attrs(v, "shortterm_reset"),
    ),
    AudiSensorEntityDescription(
        key="longterm_current",
        name="LongTerm Trip Data",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda v: _trip_data_value(v, "longterm_current"),
        extra_attrs_fn=lambda v: _trip_data_attrs(v, "longterm_current"),
    ),
    AudiSensorEntityDescription(
        key="longterm_reset",
        name="LongTerm Trip User Reset",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda v: _trip_data_value(v, "longterm_reset"),
        extra_attrs_fn=lambda v: _trip_data_attrs(v, "longterm_reset"),
    ),
    # ── Vehicle info ────────────────────────────────────────────────────
    AudiSensorEntityDescription(
        key="model",
        name="Model",
        icon="mdi:car-info",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: v.model,
        supported_fn=lambda v: bool(v.model),
    ),
    # ── Mileage / Range / Tank ──────────────────────────────────────────
    AudiSensorEntityDescription(
        key="mileage",
        name="Mileage",
        icon="mdi:counter",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        state_class=SensorStateClass.TOTAL_INCREASING,
        device_class=SensorDeviceClass.DISTANCE,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=0,
        value_fn=lambda v: parse_int(v.fields.get("UTC_TIME_AND_KILOMETER_STATUS")),
    ),
    AudiSensorEntityDescription(
        key="service_adblue_distance",
        name="AdBlue range",
        icon="mdi:map-marker-distance",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE,
        suggested_display_precision=0,
        value_fn=lambda v: parse_int(v.fields.get("ADBLUE_RANGE")),
    ),
    AudiSensorEntityDescription(
        key="range",
        name="Range",
        icon="mdi:map-marker-distance",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE,
        suggested_display_precision=0,
        value_fn=lambda v: parse_int(v.fields.get("TOTAL_RANGE")),
    ),
    AudiSensorEntityDescription(
        key="hybrid_range",
        name="hybrid Range",
        icon="mdi:map-marker-distance",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE,
        suggested_display_precision=0,
        value_fn=lambda v: _filter_unsupported(v.state.get("hybridRange")),
    ),
    AudiSensorEntityDescription(
        key="tank_level",
        name="Tank level",
        icon="mdi:gauge",
        native_unit_of_measurement=PERCENTAGE,
        value_fn=lambda v: parse_int(v.fields.get("TANK_LEVEL_IN_PERCENTAGE")),
    ),
    # ── Service / Maintenance ───────────────────────────────────────────
    AudiSensorEntityDescription(
        key="service_inspection_time",
        name="Service inspection time",
        icon="mdi:room-service-outline",
        native_unit_of_measurement=UnitOfTime.DAYS,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: parse_int(
            v.fields.get("MAINTENANCE_INTERVAL_TIME_TO_INSPECTION")
        ),
    ),
    AudiSensorEntityDescription(
        key="service_inspection_distance",
        name="Service inspection distance",
        icon="mdi:room-service-outline",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=0,
        value_fn=lambda v: parse_int(
            v.fields.get("MAINTENANCE_INTERVAL_DISTANCE_TO_INSPECTION")
        ),
    ),
    AudiSensorEntityDescription(
        key="oil_change_time",
        name="Oil change time",
        icon="mdi:oil",
        native_unit_of_measurement=UnitOfTime.DAYS,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: parse_int(
            v.fields.get("MAINTENANCE_INTERVAL_TIME_TO_OIL_CHANGE")
        ),
    ),
    AudiSensorEntityDescription(
        key="oil_change_distance",
        name="Oil change distance",
        icon="mdi:oil",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=0,
        value_fn=lambda v: parse_int(
            v.fields.get("MAINTENANCE_INTERVAL_DISTANCE_TO_OIL_CHANGE")
        ),
    ),
    AudiSensorEntityDescription(
        key="oil_level",
        name="Oil level",
        icon="mdi:oil",
        native_unit_of_measurement=PERCENTAGE,
        value_fn=lambda v: parse_float(v.fields.get("OIL_LEVEL_DIPSTICKS_PERCENTAGE"))
        if not isinstance(v.fields.get("OIL_LEVEL_DIPSTICKS_PERCENTAGE"), bool)
        else None,
        supported_fn=lambda v: (
            not isinstance(v.fields.get("OIL_LEVEL_DIPSTICKS_PERCENTAGE"), bool)
            and v.fields.get("OIL_LEVEL_DIPSTICKS_PERCENTAGE") is not None
        ),
    ),
    # ── Charging ────────────────────────────────────────────────────────
    AudiSensorEntityDescription(
        key="charging_state",
        name="Charging state",
        icon="mdi:car-battery",
        value_fn=lambda v: v.state.get("chargingState"),
    ),
    AudiSensorEntityDescription(
        key="charging_mode",
        name="Charging mode",
        value_fn=lambda v: _filter_unsupported(v.state.get("chargeMode")),
    ),
    AudiSensorEntityDescription(
        key="charging_type",
        name="Charging type",
        value_fn=lambda v: _filter_unsupported(v.state.get("chargeType")),
    ),
    AudiSensorEntityDescription(
        key="energy_flow",
        name="Energy flow",
        value_fn=lambda v: v.state.get("energyFlow"),
    ),
    AudiSensorEntityDescription(
        key="max_charge_current",
        name="Max charge current",
        icon="mdi:current-ac",
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        device_class=SensorDeviceClass.CURRENT,
        value_fn=lambda v: parse_float(v.state.get("maxChargeCurrent")),
    ),
    AudiSensorEntityDescription(
        key="actual_charge_rate",
        name="Charging rate",
        icon="mdi:electron-framework",
        native_unit_of_measurement="km/h",
        value_fn=lambda v: parse_float(v.state.get("actualChargeRate")),
    ),
    AudiSensorEntityDescription(
        key="charging_power",
        name="Charging power",
        icon="mdi:flash",
        native_unit_of_measurement=UnitOfPower.KILO_WATT,
        device_class=SensorDeviceClass.POWER,
        value_fn=lambda v: parse_float(v.state.get("chargingPower")),
    ),
    AudiSensorEntityDescription(
        key="state_of_charge",
        name="State of charge",
        native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.BATTERY,
        value_fn=lambda v: parse_int(v.state.get("stateOfCharge")),
    ),
    AudiSensorEntityDescription(
        key="remaining_charging_time",
        name="Remaining charge time",
        icon="mdi:battery-charging",
        native_unit_of_measurement=UnitOfTime.MINUTES,
        value_fn=lambda v: v.state.get("remainingChargingTime", 0),
        supported_fn=lambda v: v.state.get("carType") in ("hybrid", "electric"),
    ),
    AudiSensorEntityDescription(
        key="target_state_of_charge",
        name="Target State of charge",
        icon="mdi:ev-station",
        native_unit_of_measurement=PERCENTAGE,
        value_fn=lambda v: parse_int(v.state.get("targetstateOfCharge")),
    ),
    AudiSensorEntityDescription(
        key="external_power",
        name="External Power",
        icon="mdi:ev-station",
        value_fn=_external_power,
    ),
    AudiSensorEntityDescription(
        key="plug_led_color",
        name="Plug LED Color",
        icon="mdi:ev-plug-type1",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: v.state.get("plugledColor"),
    ),
    # ── Engine info ─────────────────────────────────────────────────────
    AudiSensorEntityDescription(
        key="primary_engine_type",
        name="Primary engine type",
        icon="mdi:engine",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _filter_unsupported(v.state.get("engineTypeFirstEngine")),
    ),
    AudiSensorEntityDescription(
        key="secondary_engine_type",
        name="Secondary engine type",
        icon="mdi:engine",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _filter_unsupported(v.state.get("engineTypeSecondEngine")),
    ),
    AudiSensorEntityDescription(
        key="primary_engine_range",
        name="Primary engine range",
        icon="mdi:map-marker-distance",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE,
        suggested_display_precision=0,
        value_fn=lambda v: _filter_unsupported(v.state.get("primaryEngineRange")),
    ),
    AudiSensorEntityDescription(
        key="secondary_engine_range",
        name="Secondary engine range",
        icon="mdi:map-marker-distance",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE,
        suggested_display_precision=0,
        value_fn=lambda v: _filter_unsupported(v.state.get("secondaryEngineRange")),
    ),
    AudiSensorEntityDescription(
        key="primary_engine_range_percent",
        name="Primary engine Percent",
        icon="mdi:gauge",
        native_unit_of_measurement=PERCENTAGE,
        value_fn=lambda v: _filter_unsupported(
            v.state.get("primaryEngineRangePercent")
        ),
    ),
    AudiSensorEntityDescription(
        key="secondary_engine_range_percent",
        name="Secondary engine Percent",
        icon="mdi:gauge",
        native_unit_of_measurement=PERCENTAGE,
        value_fn=lambda v: _filter_unsupported(
            v.state.get("secondaryEngineRangePercent")
        ),
    ),
    AudiSensorEntityDescription(
        key="car_type",
        name="Car Type",
        icon="mdi:car-info",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: _filter_unsupported(v.state.get("carType")),
    ),
    # ── Doors / trunk aggregate ─────────────────────────────────────────
    AudiSensorEntityDescription(
        key="doors_trunk_status",
        name="Doors/trunk state",
        icon="mdi:car-door",
        value_fn=lambda v: compute_doors_trunk_status(v),
        supported_fn=lambda v: compute_doors_trunk_status(v) is not None,
    ),
    # ── Climate ─────────────────────────────────────────────────────────
    AudiSensorEntityDescription(
        key="climatisation_state",
        name="Climatisation state",
        icon="mdi:air-conditioner",
        value_fn=lambda v: v.state.get("climatisationState"),
    ),
    AudiSensorEntityDescription(
        key="outdoor_temperature",
        name="Outdoor Temperature",
        icon="mdi:temperature-celsius",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        value_fn=lambda v: v.state.get("outdoorTemperature"),
    ),
    AudiSensorEntityDescription(
        key="park_time",
        name="Park Time",
        icon="mdi:car-clock",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda v: v.state.get("vehicleParkingClock"),
    ),
    AudiSensorEntityDescription(
        key="remaining_climatisation_time",
        name="Remaining Climatisation Time",
        icon="mdi:fan-clock",
        native_unit_of_measurement=UnitOfTime.MINUTES,
        value_fn=lambda v: max(0, val)
        if (val := v.state.get("remainingClimatisationTime")) is not None
        else None,
    ),
    # ── Preheater ───────────────────────────────────────────────────────
    AudiSensorEntityDescription(
        key="preheater_duration",
        name="Preheater runtime",
        icon="mdi:clock",
        native_unit_of_measurement=UnitOfTime.MINUTES,
        value_fn=lambda v: _preheater_value(v, "climatisationDuration"),
        supported_fn=lambda v: v.state.get("preheaterState") is not None,
    ),
    AudiSensorEntityDescription(
        key="preheater_remaining",
        name="Preheater remaining",
        icon="mdi:clock",
        native_unit_of_measurement=UnitOfTime.MINUTES,
        value_fn=lambda v: _preheater_value(v, "remainingClimateTime"),
        supported_fn=lambda v: v.state.get("preheaterState") is not None,
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
    coordinator = runtime_data.coordinator
    entities: list[SensorEntity] = []

    for config_vehicle in runtime_data.account.config_vehicles:
        vehicle = config_vehicle.vehicle
        for description in SENSOR_DESCRIPTIONS:
            if description.supported_fn is not None:
                supported = description.supported_fn(vehicle)
            else:
                supported = description.value_fn(vehicle) is not None
            if supported:
                entities.append(AudiSensor(coordinator, description, vehicle))

        # Charging complete time — stateful sensor, separate class
        if vehicle.state.get("carType") in ("hybrid", "electric"):
            entities.append(AudiChargingCompleteSensor(coordinator, vehicle))

    # Account-level API rate limit sensor, attached to the first vehicle.
    if runtime_data.account.config_vehicles:
        first_vehicle = runtime_data.account.config_vehicles[0].vehicle
        entities.append(
            AudiApiRateLimitSensor(
                coordinator,
                config_entry.entry_id,
                first_vehicle,
            )
        )

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Entity classes
# ---------------------------------------------------------------------------


class AudiSensor(AudiEntity, SensorEntity):
    """Representation of an Audi sensor."""

    entity_description: AudiSensorEntityDescription

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        description: AudiSensorEntityDescription,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator, vehicle)
        self.entity_description = description
        self._attr_unique_id = f"{vehicle.vin.lower()}_sensor_{description.key}"

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self._vehicle)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.extra_attrs_fn is not None:
            return self.entity_description.extra_attrs_fn(self._vehicle)
        return None


class AudiChargingCompleteSensor(AudiEntity, SensorEntity):
    """Estimated charging completion time (tracks frozen time internally)."""

    _attr_name = "Charging Complete Time"
    _attr_icon = "mdi:battery-charging"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator, vehicle)
        self._attr_unique_id = (
            f"{vehicle.vin.lower()}_sensor_charging_complete_time"
        )
        self._frozen_time = None

    @property
    def native_value(self) -> Any:
        car_type = self._vehicle.state.get("carType")
        if car_type not in ("hybrid", "electric"):
            return None
        last_update = self._vehicle.state.get("last_update_time")
        remaining = self._vehicle.state.get("remainingChargingTime", 0)
        if last_update is None or remaining is None:
            return None
        if remaining > 0:
            self._frozen_time = last_update + timedelta(minutes=remaining)
            return self._frozen_time
        return self._frozen_time


class AudiApiRateLimitSensor(AudiEntity, SensorEntity):
    """Account-level sensor exposing the Vcf-Remaining-Calls API rate limit."""

    _attr_name = "API requests remaining"
    _attr_icon = "mdi:api"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: AudiDataUpdateCoordinator,
        entry_id: str,
        vehicle: Any,
    ) -> None:
        super().__init__(coordinator, vehicle)
        self._attr_unique_id = f"{entry_id}_api_requests_remaining"

    @property
    def native_value(self) -> int | None:
        api = self.coordinator.account.connection._audi_service._api
        return api.vcf_remaining_calls


__all__ = [
    "AudiApiRateLimitSensor",
    "AudiChargingCompleteSensor",
    "AudiSensor",
    "async_setup_entry",
]
