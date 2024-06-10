"""Test automower auth."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from aiohttp import ClientError, WSServerHandshakeError

from aioautomower.exceptions import (
    ApiException,
    ApiForbiddenException,
    ApiUnauthorizedException,
    HusqvarnaWSServerHandshakeError,
)

from . import load_fixture, mock_response


async def test_connect(mock_auth):
    """Connect."""

    with patch(
        "aiohttp.client.ClientSession.ws_connect", return_value=mock_response("")
    ):
        await mock_auth.websocket_connect()

    assert mock_auth is not None

    with patch(
        "aiohttp.client.ClientSession.ws_connect",
        side_effect=WSServerHandshakeError(request_info="", history=()),
    ), pytest.raises(HusqvarnaWSServerHandshakeError) as error:
        await mock_auth.websocket_connect()

    assert error.type is HusqvarnaWSServerHandshakeError


async def test_verbs(mock_auth):
    """Test get."""

    token_fixture = json.loads(load_fixture("jwt.json"))
    json_rsp = {"a": "b"}

    for verb in ["get", "post", "patch"]:
        with patch(
            "aioautomower.auth.AbstractAuth._async_get_access_token",
            return_value=token_fixture["data"],
        ), patch("aiohttp.ClientSession.request", return_value=mock_response(json_rsp)):
            rsp = await getattr(mock_auth, verb)("https://xxx.xx.yz")
            rslt = await rsp.json()
            assert rslt == json_rsp

        with patch(
            "aioautomower.auth.AbstractAuth._async_get_access_token",
            return_value=token_fixture["data"],
        ), patch(
            "aiohttp.ClientSession.request", side_effect=[ClientError]
        ), pytest.raises(ApiException) as error:
            await getattr(mock_auth, verb)("https://xxx.xx.yz")
        assert error.type == ApiException

    for verb in ["get_json", "post_json", "patch_json"]:
        with patch(
            "aioautomower.auth.AbstractAuth._async_get_access_token",
            return_value=token_fixture["data"],
        ), patch("aiohttp.ClientSession.request", return_value=mock_response(json_rsp)):
            rsp = await getattr(mock_auth, verb)("https://xxx.xx.yz")
            assert rsp == json_rsp

        with patch(
            "aioautomower.auth.AbstractAuth._async_get_access_token",
            return_value=token_fixture["data"],
        ), patch(
            "aiohttp.ClientSession.request",
            side_effect=[mock_response("No dict"), ClientError],
        ), pytest.raises(ApiException) as error:
            await getattr(mock_auth, verb)("https://xxx.xx.yz")
        assert error.type == ApiException

        with patch(
            "aioautomower.auth.AbstractAuth._async_get_access_token",
            return_value=token_fixture["data"],
        ), patch(
            "aiohttp.ClientSession.request",
            side_effect=[mock_response(data="text", json=False)],
        ), pytest.raises(ApiException) as error:
            await getattr(mock_auth, verb)("https://xxx.xx.yz")
        assert error.type == ApiException


async def test_raise_for_status(mock_auth):
    """Test raise for status."""
    token_fixture = json.loads(load_fixture("jwt.json"))
    with patch(
        "aioautomower.auth.AbstractAuth._async_get_access_token",
        return_value=token_fixture["data"],
    ), patch(
        "aiohttp.ClientSession.request",
        return_value=mock_response({"error": "none"}, status=400),
    ), pytest.raises(ApiException) as error:
        await mock_auth.get("https://xxx.xx.yz")
    assert error.type == ApiException

    with patch(
        "aioautomower.auth.AbstractAuth._async_get_access_token",
        return_value=token_fixture["data"],
    ), patch(
        "aiohttp.ClientSession.request",
        return_value=mock_response({"error": "none"}, status=401),
    ), pytest.raises(ApiUnauthorizedException) as error:
        await mock_auth.get("https://xxx.xx.yz")
    assert error.type == ApiUnauthorizedException

    with patch(
        "aioautomower.auth.AbstractAuth._async_get_access_token",
        return_value=token_fixture["data"],
    ), patch(
        "aiohttp.ClientSession.request",
        return_value=mock_response({"error": "none"}, status=403),
    ), pytest.raises(ApiForbiddenException) as error:
        await mock_auth.get("https://xxx.xx.yz")
    assert error.type == ApiForbiddenException
