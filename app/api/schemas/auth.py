from pydantic import BaseModel


class BaseAttributes(BaseModel):
    username: str
    password: str


class BaseData(BaseModel):
    attributes: BaseAttributes


class BaseInputPayload(BaseModel):
    data: BaseData


class LoginAttributes(BaseAttributes):
    pass


class SignUpAttributes(BaseAttributes):
    account_name: str


class SignUpData(BaseData):
    attributes: SignUpAttributes


class LoginData(BaseData):
    attributes: LoginAttributes


class LoginInputPayload(BaseInputPayload):
    data: LoginData


class SignupInputPayload(BaseInputPayload):
    data: SignUpData
