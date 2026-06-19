"""Phone number enrichment — offline metadata via libphonenumber.

The OSINT ``phone`` seed had no handler. This adds country / region, carrier,
line type (mobile / fixed-line / VoIP / toll-free / …), validity and the
canonical E.164 / international formats — all computed **offline** from Google's
libphonenumber metadata bundled with the ``phonenumbers`` package (Apache-2.0).
No network, no API key. Concept aligned with flowsint's ``phone`` enrichers
(Apache-2.0; see THIRD_PARTY_LICENSES).

Numbers should be supplied in E.164 (``+<country><number>``). A bare national
number cannot be regioned reliably, so it is reported invalid with a hint.
"""
from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

_TYPE_NAMES = {
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "uan",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
}


def _parse(raw: str) -> dict:
    """Pure phone parse/enrich → profile dict. Unit-tested (offline)."""
    s = (raw or "").strip()
    if not s:
        return {"phone": raw, "valid": False, "reason": "empty"}
    try:
        num = phonenumbers.parse(s, None)
    except phonenumbers.NumberParseException as e:
        return {"phone": s, "valid": False,
                "reason": f"parse error ({e.error_type}); supply E.164 (+countrycode…)"}
    return {
        "phone": s,
        "valid": phonenumbers.is_valid_number(num),
        "possible": phonenumbers.is_possible_number(num),
        "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country_code": num.country_code,
        "region": phonenumbers.region_code_for_number(num),
        "location": geocoder.description_for_number(num, "en") or None,
        "carrier": carrier.name_for_number(num, "en") or None,
        "line_type": _TYPE_NAMES.get(phonenumbers.number_type(num), "unknown"),
        "timezones": list(timezone.time_zones_for_number(num)),
        "source": "libphonenumber (offline metadata)",
    }


async def lookup_phone(number: str) -> dict:
    """Enrich a phone number with offline libphonenumber metadata."""
    return _parse(number)
