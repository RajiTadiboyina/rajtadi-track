"""Utility script to list and delete Dynatrace Davis anomaly detector objects."""

import os
from urllib.parse import quote

import requests
from dotenv import load_dotenv


SCHEMA_ID = "builtin:davis.anomaly-detectors"


def get_dt_config() -> tuple[str, dict]:
    """Load Dynatrace base URL and API-token headers from the local `.env` file."""
    load_dotenv()

    base_url = os.environ["DT_BASE_URL"].rstrip("/")
    api_token = os.environ["DT_API_TOKEN"]
    headers = {
        "Authorization": f"Api-Token {api_token}",
        "Content-Type": "application/json",
    }
    return base_url, headers


def list_settings_objects(base_url: str, headers: dict, schema_id: str) -> list[dict]:
    """Page through Settings API results and return all objects for one schema id."""
    url = f"{base_url}/api/v2/settings/objects"
    params = {
        "schemaIds": schema_id,
        "pageSize": 500,
    }
    items: list[dict] = []
    next_page_key = None

    while True:
        request_params = dict(params)
        if next_page_key:
            request_params = {"nextPageKey": next_page_key}

        response = requests.get(url, headers=headers, params=request_params, timeout=60)
        if response.status_code != 200:
            raise RuntimeError(
                f"Failed to list settings objects: {response.status_code} {response.text[:500]}"
            )

        data = response.json()
        items.extend(data.get("items", []))
        next_page_key = data.get("nextPageKey")
        if not next_page_key:
            break

    return items


def delete_settings_object(base_url: str, headers: dict, object_id: str) -> bool:
    """Delete a single settings object and return whether the delete succeeded."""
    encoded_object_id = quote(object_id, safe="")
    url = f"{base_url}/api/v2/settings/objects/{encoded_object_id}"
    response = requests.delete(url, headers=headers, timeout=60)

    if response.status_code in (200, 204):
        return True

    print(f"Failed to delete {object_id}: {response.status_code} {response.text[:500]}")
    return False


def is_inactive_detector(item: dict) -> bool:
    """Return True when the detector is inactive/disabled in Dynatrace."""
    return item.get("value", {}).get("enabled", True) is False


def main() -> None:
    """Delete Davis anomaly detector settings objects in the configured tenant."""
    base_url, headers = get_dt_config()
    delete_only_inactive = (
        os.environ.get("DELETE_ONLY_INACTIVE", "true").strip().lower() == "true"
    )

    print(f"Listing settings objects for schema: {SCHEMA_ID}")
    objects = list_settings_objects(base_url, headers, SCHEMA_ID)
    print(f"Found {len(objects)} object(s).")

    if not objects:
        return

    objects_to_delete = objects
    if delete_only_inactive:
        objects_to_delete = [item for item in objects if is_inactive_detector(item)]
        print(
            "Configured to delete only inactive detectors "
            f"(enabled=false). Matching object(s): {len(objects_to_delete)}"
        )

    if not objects_to_delete:
        print("No matching detectors found for deletion.")
        return

    deleted = 0
    for item in objects_to_delete:
        object_id = item.get("objectId")
        value = item.get("value", {})
        title = value.get("title", "")
        enabled = value.get("enabled", True)
        if not object_id:
            continue

        print(
            f"Deleting object: {object_id} "
            f"{f'({title}) ' if title else ''}[enabled={enabled}]"
        )
        if delete_settings_object(base_url, headers, object_id):
            deleted += 1

    print(f"Deleted {deleted} of {len(objects_to_delete)} matching object(s).")


if __name__ == "__main__":
    main()
