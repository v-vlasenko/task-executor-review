from pydantic import BaseModel


class BaseAttributes(BaseModel):
    new_username: str


class BaseData(BaseModel):
    attributes: BaseAttributes


class InviteInputPayload(BaseModel):
    data: BaseData
