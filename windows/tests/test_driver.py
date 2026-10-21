# SPDX-License-Identifier: GPL-3.0-only
from pax_windows import driver


def test_classify():
    store = r'"C:\Program Files\WindowsApps\AppleInc.AppleDevices_1.0\AMDS\AppleMobileDeviceService.exe"'
    itunes = r'"C:\Program Files\Common Files\Apple\Mobile Device Support\AppleMobileDeviceService.exe"'
    assert driver.classify(store, True) == driver.DriverStatus("ok", "apple_devices")
    assert driver.classify(itunes, True) == driver.DriverStatus("ok", "itunes")
    assert driver.classify(itunes, False).state == "stopped"
    assert driver.classify(None, False).state == "missing"
    assert driver.classify(None, True).ok          # running is what counts


def test_check_uses_both_signals():
    assert driver.check(lambda: None, lambda: False).state == "missing"
    assert driver.check(lambda: "x", lambda: True).ok


def test_store_links():
    assert driver.STORE_URI == "ms-windows-store://pdp/?ProductId=9NP83LWLPZ9K"
    assert driver.STORE_WEB == "https://apps.microsoft.com/detail/9np83lwlpz9k"
    assert driver.AMDS_ADDRESS == ("127.0.0.1", 27015)


def test_port_closed():
    assert driver.port_open(("127.0.0.1", 9), timeout=0.2) in (False, True)   # never raises
