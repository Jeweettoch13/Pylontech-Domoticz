"""
<plugin key="PylontechH3X"
        name="Pylontech H3X Cloud"
        author="OpenAI / community"
        version="0.3.0"
        wikilink="https://global-ress.pylontech.com.cn/"
        externallink="https://global-ress.pylontech.com.cn/">

    <description>
        <h2>Pylontech H3X Cloud</h2>
        Cloud monitoring for Pylontech FH3X hybrid systems.<br/><br/>
        Requires a Pylontech Global RESS account.<br/>
        Tested against FH3X-15K-HY-3P-EU cloud data.
    </description>

    <params>
        <param field="Mode1" label="Pylontech Username / Email" width="350px" required="true" default="" />
        <param field="Mode2" label="Pylontech Password" width="350px" password="true" required="true" default="" />
        <param field="Mode3" label="Poll interval (seconds)" width="100px" required="true" default="60" />
        <param field="Mode4" label="Site selection (Auto or site name)" width="220px" default="Auto" />
        <param field="Mode5" label="Create extended PV string devices (Yes/No)" width="180px" default="No" />
        <param field="Mode6" label="Debug level (0/1/2)" width="100px" default="0" />
    </params>
</plugin>
"""

# -*- coding: utf-8 -*-
import base64
import binascii
import json
import math
import random
import struct
import time
from urllib.parse import quote

import Domoticz

try:
    import requests
except Exception:
    requests = None

BASE_URL = "https://global-ress.pylontech.com.cn"
TIMEOUT = 20
VERSION = "0.3.0"


# ---------------------------------------------------------------------------
# Minimal DER/RSA implementation
# Avoids requiring cryptography/pycryptodome on Synology.
# Supports SubjectPublicKeyInfo and PKCS#1 RSA public keys.
# ---------------------------------------------------------------------------

def _der_len(data, pos):
    if pos >= len(data):
        raise ValueError("DER length out of range")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7f
    if n == 0 or pos + n > len(data):
        raise ValueError("Invalid DER length")
    value = int.from_bytes(data[pos:pos+n], "big")
    return value, pos + n


def _der_tlv(data, pos=0):
    if pos >= len(data):
        raise ValueError("DER out of range")
    tag = data[pos]
    length, p = _der_len(data, pos + 1)
    end = p + length
    if end > len(data):
        raise ValueError("DER value out of range")
    return tag, p, end


def _der_children(data, start, end):
    pos = start
    while pos < end:
        tag, p, e = _der_tlv(data, pos)
        yield tag, p, e
        pos = e


def _parse_rsa_public_key_der(raw):
    """
    Return (n, e) from:
      - PKCS#1 RSAPublicKey
      - SubjectPublicKeyInfo wrapping PKCS#1
    """
    tag, p, e = _der_tlv(raw, 0)
    if tag != 0x30:
        raise ValueError("Public key is not a DER SEQUENCE")

    children = list(_der_children(raw, p, e))

    # Direct PKCS#1: SEQUENCE(INTEGER n, INTEGER e)
    ints = [c for c in children if c[0] == 0x02]
    if len(ints) >= 2:
        n = int.from_bytes(raw[ints[0][1]:ints[0][2]], "big")
        exp = int.from_bytes(raw[ints[1][1]:ints[1][2]], "big")
        return n, exp

    # SubjectPublicKeyInfo:
    # SEQUENCE(AlgorithmIdentifier, BIT STRING containing RSAPublicKey)
    bit = next((c for c in children if c[0] == 0x03), None)
    if bit is None:
        raise ValueError("No RSA public-key BIT STRING found")

    bitdata = raw[bit[1]:bit[2]]
    if not bitdata or bitdata[0] != 0:
        raise ValueError("Unsupported BIT STRING")
    return _parse_rsa_public_key_der(bitdata[1:])


def _load_public_key(text):
    s = text.strip()

    if "-----BEGIN" in s:
        lines = []
        for line in s.splitlines():
            if not line.startswith("-----"):
                lines.append(line.strip())
        raw = base64.b64decode("".join(lines))
    else:
        # Portal normally returns base64 DER. Some deployments return a
        # JSON/string-wrapped PEM.
        try:
            raw = base64.b64decode(s)
        except Exception:
            raw = s.encode("latin1")

    return _parse_rsa_public_key_der(raw)


def _rsa_pkcs1_v15_encrypt(message, public_key_text):
    n, e = _load_public_key(public_key_text)
    k = (n.bit_length() + 7) // 8
    msg = message.encode("utf-8")

    if len(msg) > k - 11:
        raise ValueError("Password too long for RSA key")

    # PKCS#1 v1.5 encryption block: 00 02 PS 00 M
    ps_len = k - len(msg) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = random.SystemRandom().randrange(1, 256)
        if b != 0:
            ps.append(b)

    em = b"\x00\x02" + bytes(ps) + b"\x00" + msg
    m = int.from_bytes(em, "big")
    c = pow(m, e, n)
    return base64.b64encode(c.to_bytes(k, "big")).decode("ascii")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_float(value, default=0.0):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _to_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def _clean_name(value):
    if value is None:
        return ""
    return str(value).strip()


def _safe_unit_name(name):
    return name[:60]


# ---------------------------------------------------------------------------
# Cloud API
# ---------------------------------------------------------------------------

class PylontechAPI(object):
    def __init__(self, username, password, debug=0):
        self.username = username
        self.password = password
        self.debug = debug
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 Chrome/140 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": BASE_URL,
            "Referer": BASE_URL + "/",
        })

    def log(self, msg, verbose=False):
        if self.debug >= (2 if verbose else 1):
            Domoticz.Log("Pylontech: " + msg)

    def _request(self, method, path, params=None, body=None):
        url = BASE_URL + path
        try:
            r = self.session.request(
                method, url, params=params, json=body, timeout=TIMEOUT
            )
        except Exception as exc:
            raise RuntimeError("HTTP error on %s: %s" % (path, exc))

        if not r.ok:
            raise RuntimeError(
                "%s returned HTTP %s" % (path, r.status_code)
            )
        try:
            return r.json()
        except Exception:
            raise RuntimeError("%s returned invalid JSON" % path)

    def get_public_key(self):
        data = self._request("GET", "/api/publicKey")
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            for key in ("data", "publicKey", "public_key", "key"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value
                if isinstance(value, dict):
                    for nested in ("publicKey", "public_key", "key", "value"):
                        nv = value.get(nested)
                        if isinstance(nv, str) and nv.strip():
                            return nv
        raise RuntimeError("Could not find public key")

    def login(self):
        key = self.get_public_key()
        encrypted = _rsa_pkcs1_v15_encrypt(self.password, key)
        result = self._request(
            "POST",
            "/api/login",
            body={
                "email": self.username,
                "password": encrypted,
                "isSoftUse": "1",
                "encryptFlag": "1",
            },
        )
        if not isinstance(result, dict) or result.get("code") != 200:
            raise RuntimeError("Login failed")
        token = result.get("token")
        if not token:
            raise RuntimeError("Login response contained no token")
        self.session.headers.update({"Authorization": "Bearer " + token})
        return True

    def get_systems(self):
        data = self._request(
            "GET",
            "/api/system/runMonitor/getSiteSystemListByTypeValue"
        )
        found = []

        def walk(v):
            if isinstance(v, dict):
                site = v.get("siteId") or v.get("site_id")
                system = v.get("systemId") or v.get("system_id")
                if site and system:
                    found.append(v)
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)

        walk(data)

        unique = []
        seen = set()
        for x in found:
            key = (
                str(x.get("siteId") or x.get("site_id")),
                str(x.get("systemId") or x.get("system_id")),
            )
            if key not in seen:
                seen.add(key)
                unique.append(x)

        return unique

    def get_site_info(self):
        try:
            return self._request(
                "POST",
                "/api/system/runMonitor/getSiteInfo",
                body={}
            )
        except Exception:
            return None

    def get_realtime(self, site_id, system_id):
        return self._request(
            "POST",
            "/api/system/runMonitor/getSiteRealtime"
            "?siteId=%s&systemId=%s" % (
                quote(str(site_id), safe=""),
                quote(str(system_id), safe="")
            )
        )

    def get_today_energy(self):
        return self._request(
            "GET",
            "/api/system/runMonitor/getTodDayEnergy"
        )

    def get_today_warnings(self):
        return self._request(
            "GET",
            "/api/system/runMonitor/getTodDayWarnNumV1"
        )


# ---------------------------------------------------------------------------
# Domoticz devices
# ---------------------------------------------------------------------------

class DeviceDef(object):
    def __init__(self, unit, name, dtype, subtype, options=None, switchtype=0):
        self.unit = unit
        self.name = name
        self.dtype = dtype
        self.subtype = subtype
        self.options = options or {}
        self.switchtype = switchtype


# Domoticz legacy-plugin device definitions.
# Custom numeric values use Type=243 / Subtype=31 with Options={"Custom":"1;unit"}.
# Voltage = subtype 8, percentage = subtype 6, current = subtype 23,
# temperature = Type 80/Subtype 5, text = Type 243/Subtype 19.
DEVICES = [
    # Battery
    DeviceDef(1,  "H3X - Battery - SoC",                    243, 6,  {"Custom": "1;%"}),
    DeviceDef(2,  "H3X - Battery - SoH",                    243, 6,  {"Custom": "1;%"}),
    DeviceDef(3,  "H3X - Battery - Power",                  243, 31, {"Custom": "1;kW"}),
    DeviceDef(4,  "H3X - Battery - Voltage",                243, 8,  {"Custom": "1;V"}),
    DeviceDef(5,  "H3X - Battery - Current",                243, 23, {}),
    DeviceDef(6,  "H3X - Battery - Packs",                  243, 31, {"Custom": "1;packs"}),
    DeviceDef(7,  "H3X - Battery - Module Max Voltage",     243, 8,  {"Custom": "1;V"}),
    DeviceDef(8,  "H3X - Battery - Module Min Voltage",     243, 8,  {"Custom": "1;V"}),
    DeviceDef(9,  "H3X - Battery - Cell Max Voltage",       243, 8,  {"Custom": "1;V"}),
    DeviceDef(10, "H3X - Battery - Cell Min Voltage",       243, 8,  {"Custom": "1;V"}),
    DeviceDef(11, "H3X - Battery - Cell Max Temperature",   80,  5,  {}),
    DeviceDef(12, "H3X - Battery - Cell Min Temperature",   80,  5,  {}),
    DeviceDef(13, "H3X - Battery - Cell Max Temp Number",   243, 31, {"Custom": "1;cell"}),
    DeviceDef(14, "H3X - Battery - Cell Min Temp Number",   243, 31, {"Custom": "1;cell"}),
    DeviceDef(15, "H3X - Battery - Cell Max Voltage Number",243, 31, {"Custom": "1;cell"}),
    DeviceDef(16, "H3X - Battery - Cell Min Voltage Number",243, 31, {"Custom": "1;cell"}),
    DeviceDef(17, "H3X - Battery - PCS Temperature",        80,  5,  {}),
    DeviceDef(18, "H3X - Battery - Internal Temperature",   80,  5,  {}),
    DeviceDef(19, "H3X - Battery - BMS Version",            243, 19, {}),
    DeviceDef(33, "H3X - Battery - Module Max Temperature", 80,  5,  {}),
    DeviceDef(34, "H3X - Battery - Module Min Temperature", 80,  5,  {}),
    DeviceDef(35, "H3X - Battery - Module Max Temp Number", 243, 31, {"Custom": "1;module"}),
    DeviceDef(36, "H3X - Battery - Module Min Temp Number", 243, 31, {"Custom": "1;module"}),
    DeviceDef(37, "H3X - Battery - Module IDs",             243, 19, {}),
    DeviceDef(38, "H3X - Battery - Module Max Voltage Number", 243, 31, {"Custom": "1;module"}),
    DeviceDef(39, "H3X - Battery - Module Min Voltage Number", 243, 31, {"Custom": "1;module"}),

    # PV
    DeviceDef(20, "H3X - PV - Total Power",                 243, 31, {"Custom": "1;kW"}),
    DeviceDef(21, "H3X - PV - Today",                       243, 31, {"Custom": "1;kWh"}),
    DeviceDef(22, "H3X - PV1 - Power",                     243, 31, {"Custom": "1;kW"}),
    DeviceDef(23, "H3X - PV1 - Voltage",                   243, 8,  {"Custom": "1;V"}),
    DeviceDef(24, "H3X - PV1 - Current",                   243, 23, {}),
    DeviceDef(25, "H3X - PV2 - Power",                     243, 31, {"Custom": "1;kW"}),
    DeviceDef(26, "H3X - PV2 - Voltage",                   243, 8,  {"Custom": "1;V"}),
    DeviceDef(27, "H3X - PV2 - Current",                   243, 23, {}),
    DeviceDef(28, "H3X - PV3 - Power",                     243, 31, {"Custom": "1;kW"}),
    DeviceDef(29, "H3X - PV3 - Voltage",                   243, 8,  {"Custom": "1;V"}),
    DeviceDef(30, "H3X - PV3 - Current",                   243, 23, {}),
    DeviceDef(31, "H3X - PV4 - Voltage",                   243, 8,  {"Custom": "1;V"}),
    DeviceDef(32, "H3X - PV Status",                        243, 19, {}),

    # Grid
    DeviceDef(40, "H3X - Grid - Power",                    243, 31, {"Custom": "1;kW"}),
    DeviceDef(41, "H3X - Grid - R Voltage",                243, 8,  {"Custom": "1;V"}),
    DeviceDef(42, "H3X - Grid - S Voltage",                243, 8,  {"Custom": "1;V"}),
    DeviceDef(43, "H3X - Grid - T Voltage",                243, 8,  {"Custom": "1;V"}),
    DeviceDef(44, "H3X - Grid - R Current",                243, 23, {}),
    DeviceDef(45, "H3X - Grid - S Current",                243, 23, {}),
    DeviceDef(46, "H3X - Grid - T Current",                243, 23, {}),
    DeviceDef(47, "H3X - Grid - R Power",                  243, 31, {"Custom": "1;kW"}),
    DeviceDef(48, "H3X - Grid - S Power",                  243, 31, {"Custom": "1;kW"}),
    DeviceDef(49, "H3X - Grid - T Power",                  243, 31, {"Custom": "1;kW"}),
    DeviceDef(50, "H3X - Grid - Power Factor",             243, 31, {"Custom": "1;PF"}),
    DeviceDef(51, "H3X - Grid - Meter R Voltage",          243, 8,  {"Custom": "1;V"}),
    DeviceDef(52, "H3X - Grid - Meter S Voltage",          243, 8,  {"Custom": "1;V"}),
    DeviceDef(53, "H3X - Grid - Meter T Voltage",          243, 8,  {"Custom": "1;V"}),
    DeviceDef(54, "H3X - Grid Status",                      243, 19, {}),

    # Load
    DeviceDef(60, "H3X - Load - Power",                    243, 31, {"Custom": "1;kW"}),
    DeviceDef(61, "H3X - Load - Today",                    243, 31, {"Custom": "1;kWh"}),
    DeviceDef(62, "H3X - Load - R Power",                  243, 31, {"Custom": "1;kW"}),
    DeviceDef(63, "H3X - Load - S Power",                  243, 31, {"Custom": "1;kW"}),
    DeviceDef(64, "H3X - Load - T Power",                  243, 31, {"Custom": "1;kW"}),
    DeviceDef(65, "H3X - Load - R Voltage",                243, 8,  {"Custom": "1;V"}),
    DeviceDef(66, "H3X - Load - S Voltage",                243, 8,  {"Custom": "1;V"}),
    DeviceDef(67, "H3X - Load - T Voltage",                243, 8,  {"Custom": "1;V"}),
    DeviceDef(68, "H3X - Load - R Current",                243, 23, {}),
    DeviceDef(69, "H3X - Load - S Current",                243, 23, {}),
    DeviceDef(70, "H3X - Load - T Current",                243, 23, {}),
    DeviceDef(71, "H3X - Load Status",                      243, 19, {}),

    # PCS
    DeviceDef(80, "H3X - PCS - Power",                     243, 31, {"Custom": "1;kW"}),
    DeviceDef(81, "H3X - PCS - R Voltage",                 243, 8,  {"Custom": "1;V"}),
    DeviceDef(82, "H3X - PCS - S Voltage",                 243, 8,  {"Custom": "1;V"}),
    DeviceDef(83, "H3X - PCS - T Voltage",                 243, 8,  {"Custom": "1;V"}),
    DeviceDef(84, "H3X - PCS - R Current",                 243, 23, {}),
    DeviceDef(85, "H3X - PCS - S Current",                 243, 23, {}),
    DeviceDef(86, "H3X - PCS - T Current",                 243, 23, {}),
    DeviceDef(87, "H3X - PCS - Version",                   243, 19, {}),
    DeviceDef(88, "H3X - PCS - Bus Voltage",               243, 8,  {"Custom": "1;V"}),
    DeviceDef(89, "H3X - PCS - State",                     243, 19, {}),

    # EPS / backup output
    DeviceDef(100, "H3X - EPS - Total Power",              243, 31, {"Custom": "1;kW"}),
    DeviceDef(101, "H3X - EPS - R Voltage",               243, 8,  {"Custom": "1;V"}),
    DeviceDef(102, "H3X - EPS - S Voltage",               243, 8,  {"Custom": "1;V"}),
    DeviceDef(103, "H3X - EPS - T Voltage",               243, 8,  {"Custom": "1;V"}),
    DeviceDef(104, "H3X - EPS - R Current",               243, 23, {}),
    DeviceDef(105, "H3X - EPS - S Current",               243, 23, {}),
    DeviceDef(106, "H3X - EPS - T Current",               243, 23, {}),

    # Energy / totals
    DeviceDef(120, "H3X - Energy - Charge Today",          243, 31, {"Custom": "1;kWh"}),
    DeviceDef(121, "H3X - Energy - Discharge Today",       243, 31, {"Custom": "1;kWh"}),
    DeviceDef(122, "H3X - Energy - Grid Import",           243, 31, {"Custom": "1;kWh"}),
    DeviceDef(123, "H3X - Energy - Grid Export",           243, 31, {"Custom": "1;kWh"}),
    DeviceDef(124, "H3X - Energy - Historical Charge",     243, 31, {"Custom": "1;kWh"}),
    DeviceDef(125, "H3X - Energy - Historical Discharge",  243, 31, {"Custom": "1;kWh"}),
    DeviceDef(126, "H3X - Energy - PV Today",              243, 31, {"Custom": "1;kWh"}),

    # Parallel / system overview
    DeviceDef(140, "H3X - Parallel - PV Power",            243, 31, {"Custom": "1;kW"}),
    DeviceDef(141, "H3X - Parallel - Battery Power",       243, 31, {"Custom": "1;kW"}),
    DeviceDef(142, "H3X - Parallel - Grid Power",          243, 31, {"Custom": "1;kW"}),
    DeviceDef(143, "H3X - Parallel - Load Power",          243, 31, {"Custom": "1;kW"}),
    DeviceDef(144, "H3X - Parallel - Grid Load Power",     243, 31, {"Custom": "1;kW"}),
    DeviceDef(145, "H3X - Parallel - EPS Power",           243, 31, {"Custom": "1;kW"}),
    DeviceDef(146, "H3X - Parallel Mode",                  243, 19, {}),

    # Status / identification
    DeviceDef(160, "H3X - Communication",                  243, 19, {}),
    DeviceDef(161, "H3X - Inverter State",                 243, 19, {}),
    DeviceDef(162, "H3X - Site",                            243, 19, {}),
    DeviceDef(163, "H3X - Device Model",                   243, 19, {}),
    DeviceDef(164, "H3X - BMS Serial",                     243, 19, {}),
    DeviceDef(165, "H3X - Device Serial",                  243, 19, {}),
    DeviceDef(166, "H3X - Alarm Summary",                  243, 19, {}),
    DeviceDef(167, "H3X - Alarm Count Today",              243, 31, {"Custom": "1;alarms"}),
    DeviceDef(168, "H3X - Firmware - PCS",                243, 19, {}),
    DeviceDef(169, "H3X - Firmware - BMS",                243, 19, {}),
]


class BasePlugin(object):
    def __init__(self):
        self.api = None
        self.system = None
        self.monitor = {}
        self.site_monitor = {}
        self.warnings = {}
        self.last_poll = 0
        self.poll_interval = 60
        self.debug = 0
        self.started = False

    def log(self, msg, level=1):
        if self.debug >= level:
            Domoticz.Log("Pylontech: " + msg)

    def ensure_device(self, definition):
        if definition.unit not in Devices:
            Domoticz.Device(
                Unit=definition.unit,
                Name=definition.name,
                Type=definition.dtype,
                Subtype=definition.subtype,
                Used=1,
                Options=definition.options
            ).Create()
            self.log("Created device %d: %s" % (definition.unit, definition.name), 2)
        else:
            # Keep existing devices untouched. For a clean type/subtype migration,
            # remove the old hardware and add it again with this plugin version.
            pass

    def create_devices(self):
        for d in DEVICES:
            self.ensure_device(d)

    def update(self, unit, value, text=None):
        if unit not in Devices:
            return
        if text is None:
            s = "%.2f" % _to_float(value)
        else:
            s = str(text)
        Devices[unit].Update(0, s)

    def _alarm_list(self):
        data = self.warnings
        if not isinstance(data, dict):
            return []
        raw = data.get("data")
        if isinstance(raw, dict):
            for key in ("records", "list", "rows", "alarmList", "data"):
                if isinstance(raw.get(key), list):
                    return raw.get(key)
        if isinstance(raw, list):
            return raw
        return []

    def _alarm_count(self):
        return len(self._alarm_list())

    def _alarm_summary(self):
        alarms = self._alarm_list()
        if not alarms:
            return "No alarms today"
        last = alarms[0] if isinstance(alarms[0], dict) else {}
        name = last.get("alarmNameEn") or last.get("alarmName") or "Alarm"
        status = "released" if last.get("releaseTime") else "active"
        return "%s (%s)" % (str(name), status)

    def _firmware_value(self, key):
        value = self.monitor.get(key)
        return "" if value is None else str(value)

    def update_all(self):
        d = self.monitor
        sm = self.site_monitor

        mapping = {
            # Battery
            1: d.get("soc"),
            2: d.get("soh"),
            3: d.get("batterypower"),
            4: d.get("totalvoltage"),
            5: d.get("currentah"),
            6: d.get("battery_pack"),
            7: d.get("modulemaxvoltage"),
            8: d.get("moduleminvoltage"),
            9: d.get("simplemaxvoltage"),
            10: d.get("simpleminvoltage"),
            11: d.get("simplehightem"),
            12: d.get("simplelowtem"),
            13: d.get("simplehightemnumber"),
            14: d.get("simplelowtemnumber"),
            15: d.get("simplehighestnumber"),
            16: d.get("simplelownumber"),
            17: d.get("temperature"),
            18: d.get("internalambienttemperature"),
            19: d.get("bms_version"),
            33: d.get("modulehightem"),
            34: d.get("modulelowtem"),
            35: d.get("modulehightemnumber"),
            36: d.get("modulelownumber"),
            37: d.get("batteryblock"),
            38: d.get("modulehighestnumber"),
            39: d.get("modulelownumber"),

            # PV
            20: d.get("pvpower"),
            21: _to_float(d.get("pvtodayenergy")) / 10.0,
            22: d.get("pv1power"),
            23: d.get("pv1voltage"),
            24: d.get("pv1current"),
            25: d.get("pv2power"),
            26: d.get("pv2voltage"),
            27: d.get("pv2current"),
            28: d.get("pv3power"),
            29: d.get("pv3voltage"),
            30: d.get("pv3current"),
            31: d.get("pv4voltage"),
            32: d.get("pvStatus"),

            # Grid
            40: sm.get("meterPower", d.get("meterpower")),
            41: d.get("gridrvoltage"),
            42: d.get("gridsvoltage"),
            43: d.get("gridtvoltage"),
            44: d.get("gridctrcurrent"),
            45: d.get("gridctscurrent"),
            46: d.get("gridcttcurrent"),
            47: d.get("gridpowerr"),
            48: d.get("gridpowers"),
            49: d.get("gridpowert"),
            50: d.get("outputpf"),
            51: d.get("meterRVoltage"),
            52: d.get("meterSVoltage"),
            53: d.get("meterTVoltage"),
            54: sm.get("gridStatus", d.get("gridStatus")),

            # Load
            60: d.get("loadpower"),
            61: _to_float(d.get("loadtodaykwh")) / 10.0,  # API reports tenths of kWh
            62: d.get("totalLoadPowerR"),
            63: d.get("totalLoadPowerS"),
            64: d.get("totalLoadPowerT"),
            65: d.get("loadrvoltage"),
            66: d.get("loadsvoltage"),
            67: d.get("loadtvoltage"),
            68: d.get("loadrcurrent"),
            69: d.get("loadscurrent"),
            70: d.get("loadtcurrent"),
            71: d.get("loadStatus"),

            # PCS
            80: d.get("pcspower"),
            81: d.get("pcsrvoltage"),
            82: d.get("pcssvoltage"),
            83: d.get("pcstvoltage"),
            84: d.get("pcsrcurrent"),
            85: d.get("pcsscurrent"),
            86: d.get("pcstcurrent"),
            87: d.get("pcsversion"),
            88: d.get("busvoltage"),
            89: d.get("inverterstate"),

            # EPS
            100: d.get("epsTotalPower"),
            101: d.get("epsrvoltage"),
            102: d.get("epssvoltage"),
            103: d.get("epstvoltage"),
            104: d.get("epsrcurrent"),
            105: d.get("epsscurrent"),
            106: d.get("epstcurrent"),

            # Energy
            120: d.get("dailyaccumulatechargecapacity"),
            121: d.get("dailyaccumulatedischargecapacity"),
            122: d.get("importenergyfrommeter"),
            123: d.get("exportenergyfrommeter"),
            124: d.get("historyaccumulatechargecapacity"),
            125: d.get("historyaccumulatedischargecapacity"),
            126: _to_float(d.get("pvtodayenergy")) / 10.0,  # API reports tenths of kWh

            # Parallel
            140: d.get("parallelPvPower"),
            141: d.get("parallelBatteryPower"),
            142: d.get("parallelGridPower"),
            143: d.get("parallelLoadPower"),
            144: d.get("parallelGridLoadPower"),
            145: d.get("parallelEpsPower"),
            146: d.get("parallelMode"),

            # Status / identity
            160: d.get("communicateStatus"),
            161: d.get("inverterstate"),
            162: sm.get("siteName", ""),
            163: self.system.get("deviceModel", "") if self.system else "",
            164: d.get("bms_sn"),
            165: self.system.get("deviceId", "") if self.system else d.get("sn"),
            166: self._alarm_summary(),
            167: self._alarm_count(),
            168: self._firmware_value("pcsversion"),
            169: self._firmware_value("bms_version"),
        }

        text_units = set([19, 32, 37, 54, 71, 87, 89, 146, 160, 161, 162, 163, 164, 165, 166, 168, 169])
        temp_units = set([11, 12, 17, 18, 33, 34])
        for unit, value in mapping.items():
            if unit in text_units:
                if value is None:
                    value = ""
                self.update(unit, value, text=str(value))
            elif unit in temp_units:
                if value is not None:
                    self.update(unit, value, text="%.1f" % _to_float(value))
            else:
                self.update(unit, value)

        # Put the useful cell location next to the extrema values.
        if 11 in Devices:
            Devices[11].Update(0, "%.1f" % _to_float(d.get("simplehightem")))
        if 12 in Devices:
            Devices[12].Update(0, "%.1f" % _to_float(d.get("simplelowtem")))

        self.log(
            "Updated: SoC %.1f%% | PV %.2f kW | Battery %.2f kW | Grid %.2f kW | Load %.2f kW"
            % (
                _to_float(d.get("soc")),
                _to_float(d.get("pvpower")),
                _to_float(d.get("batterypower")),
                _to_float(sm.get("meterPower", d.get("meterpower"))),
                _to_float(d.get("loadpower")),
            ),
            1,
        )

    def choose_system(self, systems):
        if not systems:
            raise RuntimeError("No Pylontech systems found")

        wanted = _clean_name(Parameters.get("Mode4", "Auto")).lower()
        if wanted and wanted != "auto":
            for s in systems:
                if _clean_name(s.get("siteName")).lower() == wanted:
                    return s
                if _clean_name(s.get("systemName")).lower() == wanted:
                    return s

        # Prefer FH3X when system list contains identifying fields.
        for s in systems:
            text = json.dumps(s).lower()
            if "fh3x" in text:
                return s
        return systems[0]

    def poll(self):
        if requests is None:
            raise RuntimeError("Python module 'requests' is missing")

        systems = self.api.get_systems()
        self.system = self.choose_system(systems)

        site_id = self.system.get("siteId") or self.system.get("site_id")
        system_id = self.system.get("systemId") or self.system.get("system_id")
        if not site_id or not system_id:
            raise RuntimeError("Selected system has no siteId/systemId")

        realtime = self.api.get_realtime(site_id, system_id)
        data = realtime.get("data", {}) if isinstance(realtime, dict) else {}
        monitors = data.get("deviceMonitor") or []
        if not monitors:
            raise RuntimeError("Cloud returned no deviceMonitor data")

        self.monitor = monitors[0] or {}
        self.site_monitor = data.get("siteMonitorPowerVo") or {}
        try:
            self.warnings = self.api.get_today_warnings() or {}
        except Exception as exc:
            self.warnings = {}
            self.log("Warning query failed: %s" % exc, 2)

        self.create_devices()
        self.update_all()

        # Store only non-sensitive state for diagnostics. Never token/cookies/password.
        try:
            state = {
                "plugin_version": VERSION,
                "site_id": site_id,
                "system_id": system_id,
                "site_name": self.site_monitor.get("siteName") or self.monitor.get("site_name"),
                "device_model": self.system.get("deviceModel"),
                "last_update": self.monitor.get("save_time"),
                "soc": self.monitor.get("soc"),
                "battery_pack": self.monitor.get("battery_pack"),
            }
            with open("pylontech_h3x_state.json", "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass


class Plugin(BasePlugin):
    pass


# ---------------------------------------------------------------------------
# Domoticz lifecycle
# ---------------------------------------------------------------------------

class MainPlugin(object):
    def __init__(self):
        self.core = Plugin()

    def onStart(self):
        if requests is None:
            Domoticz.Error(
                "Pylontech: Python requests module is required. "
                "Install requests in the Python environment used by Domoticz."
            )
            return

        self.core.debug = _to_int(Parameters.get("Mode6", "0"), 0)
        self.core.poll_interval = max(
            30, _to_int(Parameters.get("Mode3", "60"), 60)
        )

        username = _clean_name(Parameters.get("Mode1", ""))
        password = Parameters.get("Mode2", "")

        if not username or not password:
            Domoticz.Error("Pylontech: Username and Password are required.")
            return

        try:
            self.core.api = PylontechAPI(username, password, self.core.debug)
            Domoticz.Log(
                "Pylontech H3X Cloud v%s starting..." % VERSION
            )
            self.core.api.login()
            Domoticz.Log("Pylontech: Cloud login successful.")
            self.core.poll()
            self.core.last_poll = time.time()
            self.core.started = True
            Domoticz.Heartbeat(10)
        except Exception as exc:
            Domoticz.Error("Pylontech: startup failed: %s" % exc)

    def onStop(self):
        Domoticz.Log("Pylontech: stopped.")

    def onHeartbeat(self):
        if not self.core.started:
            return

        now = time.time()
        if now - self.core.last_poll < self.core.poll_interval:
            return

        try:
            self.core.poll()
            self.core.last_poll = now
        except Exception as exc:
            Domoticz.Error("Pylontech: poll failed: %s" % exc)


_instance = MainPlugin()


def onStart():
    _instance.onStart()


def onStop():
    _instance.onStop()


def onHeartbeat():
    _instance.onHeartbeat()


def onCommand(Unit, Command, Level, Color):
    # Cloud plugin is read-only in v0.1.0.
    Domoticz.Log(
        "Pylontech: command ignored; cloud plugin is read-only in v0.3.0."
    )
