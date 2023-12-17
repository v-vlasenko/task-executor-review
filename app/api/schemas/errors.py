from typing import TypedDict, List


class JsonApiError(TypedDict):
    status: str
    detail: str


class JsonApiErrorResponse(TypedDict):
    errors: List[JsonApiError]
