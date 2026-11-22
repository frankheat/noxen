"""Stable display order for provider requests, preserving captured fields."""

ARGUMENT_ORDER = (
    "uri", "authority", "projection", "selection", "selectionArgs", "sortOrder",
    "queryArguments", "method", "arg", "mode", "mimeType", "values", "extras",
    "maxRows", "maxBytes",
)


def ordered_provider_arguments(arguments):
    result = {}
    keys = [key for key in ARGUMENT_ORDER if key in arguments]
    keys.extend(sorted(set(arguments) - set(keys)))
    for key in keys:
        value = arguments[key]
        if key == "queryArguments" and isinstance(value, dict):
            value = ordered_provider_arguments(value)
        elif key in ("values", "extras") and isinstance(value, dict):
            items = {}
            for name in sorted(value):
                item = value[name]
                if isinstance(item, dict):
                    fields = [field for field in ("type", "value") if field in item]
                    fields.extend(sorted(set(item) - set(fields)))
                    item = {field: item[field] for field in fields}
                items[name] = item
            value = items
        result[key] = value
    return result


def ordered_provider_request(request):
    arguments = {key: value for key, value in request.items() if key != "operation"}
    return {"operation": request["operation"], **ordered_provider_arguments(arguments)}
