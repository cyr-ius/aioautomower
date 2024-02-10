"""Tests for asynchronous Python client for aioautomower."""

import json

import pytest

from aioautomower.utils import async_structure_token, mower_list_to_dictionary_dataclass
from tests import load_fixture

MOWER_ID = "c7233734-b219-4287-a173-08e3643f89f0"


@pytest.mark.asyncio
async def test_low_feature_mower() -> None:
    """Test converting a low feature mower."""
    mower_fixture = load_fixture("low_feature_mower.json")
    mower_python = json.loads(mower_fixture)
    mowers = mower_list_to_dictionary_dataclass(mower_python)
    assert mowers[MOWER_ID].headlight.mode is None
    assert mowers[MOWER_ID].cutting_height is None
    assert len(mowers[MOWER_ID].positions) == 0


@pytest.mark.asyncio
async def test_standard_mower() -> None:
    """Test converting a standard mower."""
    mower_fixture = load_fixture("mower.json")
    mower_python = json.loads(mower_fixture)
    mowers = mower_list_to_dictionary_dataclass(mower_python)
    assert mowers[MOWER_ID].battery.battery_percent == 100
    assert mowers[MOWER_ID].work_areas is None
    assert mowers[MOWER_ID].statistics.cutting_blade_usage_time == 0
    assert len(mowers[MOWER_ID].positions) != 0


@pytest.mark.asyncio
async def test_high_feature_mower() -> None:
    """Test converting a high feature mower."""
    mower_fixture = load_fixture("high_feature_mower.json")
    mower_python = json.loads(mower_fixture)
    mowers = mower_list_to_dictionary_dataclass(mower_python)
    assert mowers[MOWER_ID].battery.battery_percent == 100
    assert mowers[MOWER_ID].stay_out_zones.dirty is False
    assert (
        mowers[MOWER_ID].stay_out_zones.zones[0].id
        == "81C6EEA2-D139-4FEA-B134-F22A6B3EA403"
    )
    assert mowers[MOWER_ID].stay_out_zones.zones[0].name == "Springflowers"
    assert mowers[MOWER_ID].stay_out_zones.zones[0].enabled is True
    assert mowers[MOWER_ID].work_areas is not None
    assert mowers[MOWER_ID].work_areas[0].work_area_id == 123456
    assert mowers[MOWER_ID].work_areas[0].name == "Front lawn"
    assert mowers[MOWER_ID].work_areas[0].cutting_height == 50
    assert mowers[MOWER_ID].statistics.cutting_blade_usage_time == 1234
    assert len(mowers[MOWER_ID].positions) != 0


@pytest.mark.asyncio
async def test_decode_token() -> None:
    """Test converting a low feature mower."""
    token_fixture = load_fixture("jwt")
    token_structered = await async_structure_token(token_fixture)
    assert token_structered.scope == "iam:read amc:api"
    assert token_structered.client_id == "433e5fdf-5129-452c-xxxx-fadce3213042"
    assert token_structered.user.first_name == "Erika"
    assert token_structered.user.last_name == "Mustermann"
