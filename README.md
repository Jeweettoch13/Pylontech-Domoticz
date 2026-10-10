# Pylontech H3X Domoticz Plugin v0.3.0

Cloud monitoring plugin for Pylontech FH3X hybrid systems.

Test target: **FH3X-15K-HY-3P-EU** using the Pylontech Global RESS portal.

## v0.3.0

- Expanded battery/module information.
- Added module max/min temperature and module number information.
- Added battery module ID list.
- Added alarm summary and today's alarm count.
- Added PCS/BMS firmware fields.
- Corrected PV Today and Load Today scaling: the observed cloud fields are tenths of kWh (e.g. 121 -> 12.1 kWh, 331 -> 33.1 kWh).
- Keeps the plugin read-only.
- Does not persist Pylontech passwords, JWT tokens or cookies.
- Designed for older Synology/Docker Python environments; RSA PKCS#1 v1.5 is implemented without cryptography/pycryptodome.

## Installation

0. Global ress account required trough https://global-ress.pylontech.com.cn/login
1. Unzip the `PylontechH3X` directory into the Domoticz Python plugins directory.
2. Restart Domoticz.
3. Go to **Setup -> Hardware -> Add Hardware**.
4. Select **Pylontech H3X Cloud**.
5. Enter Pylontech email and password.
6. Leave site selection at `Auto` unless multiple sites are present.
7. Start with a 60 second poll interval.

## Important Docker note

Keep your existing `/opt/domoticz/userdata` volume untouched. The plugin creates its own devices and does not alter or replace the Domoticz database.
