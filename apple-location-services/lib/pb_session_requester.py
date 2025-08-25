import struct
import urllib
from http.client import HTTPResponse
from typing import Optional
from urllib.request import Request


def read_big_endian_fixed_16(buf: bytes) -> int:
    """
    References:
    -[PBDataReader readBigEndianFixed16]
    """
    return struct.unpack('!h', buf)[0]


def read_big_endian_fixed_32(buf: bytes) -> int:
    """
    References:
    -[PBDataReader readBigEndianFixed32]
    """
    return struct.unpack('!i', buf)[0]


def write_big_endian_fixed_16(value: int) -> bytes:
    """
    References:
    -[PBDataWriter writeBigEndianFixed16:]
    """
    return struct.pack('!h', value)


def write_big_endian_fixed_32(value: int) -> bytes:
    """
    References:
    -[PBDataWriter writeBigEndianFixed32:]
    """
    return struct.pack('!i', value)


def write_big_endian_short_then_string(text: str) -> bytes:
    """
    References:
    -[PBDataWriter writeBigEndianShortThenString:]
    """
    text_bytes = text.encode()
    return_bytes = struct.pack('!h', len(text_bytes))
    return_bytes += text_bytes
    return return_bytes


class PBRequestPreamble:
    protocol_version = 1
    locale_country = 'en-001_001'
    application_id = 'com.apple.locationd'
    os_version = '18.6.2.22G100'

    def __init__(self, local_country: Optional[str] = None, application_id: Optional[str] = None,
                 os_version: Optional[str] = None):
        if local_country is not None:
            self.locale_country = local_country
        if application_id is not None:
            self.application_id = application_id
        if os_version is not None:
            self.os_version = os_version

    def to_binary(self) -> bytes:
        """
        References:
        -[PBSessionRequester requestPreamble]
        """
        buf = write_big_endian_fixed_16(self.protocol_version)
        buf += write_big_endian_short_then_string(self.locale_country)
        buf += write_big_endian_short_then_string(self.application_id)
        buf += write_big_endian_short_then_string(self.os_version)
        return buf


class PBResponsePreamble:
    protocol_version: int

    def __init__(self, protocol_version: int):
        self.protocol_version = protocol_version

    @property
    def byte_count(self):
        return 2

    @staticmethod
    def from_binary(buf: bytes) -> 'PBResponsePreamble':
        """
        References:
        -[PBSessionRequester readResponsePreamble:]
        """
        protocol_version = read_big_endian_fixed_16(buf[:2])
        return PBResponsePreamble(protocol_version)


class PBRequest:
    def __init__(self, type_code: int, data: bytes):
        self.type_code = type_code
        self.data = data

    def to_binary(self) -> bytes:
        """
        References:
        -[PBSessionRequester writeRequest:into:]
        -[PBDataWriter writeProtoBuffer:]
        :return:
        """
        buf = write_big_endian_fixed_32(self.type_code)
        buf += write_big_endian_fixed_32(len(self.data))
        buf += self.data
        return buf


class PBResponse:
    type_code: int
    data_length: int
    data: bytes

    def __init__(self, type_code: int, data_length: int, data: bytes):
        self.type_code = type_code
        self.data_length = data_length
        self.data = data

    @property
    def byte_count(self):
        return 4 + 4 + self.data_length

    @staticmethod
    def from_binary(buf: bytes) -> 'PBResponse':
        """
        References:
        -[PBSessionRequester _tryParseData]
        -[PBSessionRequester tryReadResponseData:forRequest:forResponseClass:]
        -[PBDataReader readProtoBuffer]
        """
        offset = 0

        type_code = read_big_endian_fixed_32(buf[offset:4])
        offset += 4

        data_length = read_big_endian_fixed_32(buf[offset:offset + 4])
        offset += 4

        data = buf[offset:offset + data_length]

        return PBResponse(type_code, data_length, data)


class PBSessionRequester:
    """ A reimplementation of the PBSessionRequester part of the ProtocolBuffer.framework """

    endpoint: str
    headers = {
        'User-Agent': 'locationd/2964.0.8 CFNetwork/3826.600.41 Darwin/24.6.0',
        'Accept': '*/*',
        'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    preamble: PBRequestPreamble

    def __init__(self, endpoint: str, headers: Optional[dict] = None, preamble: Optional[PBRequestPreamble] = None):
        self.endpoint = endpoint
        if headers is not None:
            self.headers.update(headers)
        self.preamble = preamble if preamble is not None else PBRequestPreamble()

    def _send_http_request(self, requests: list[PBRequest]) -> list[PBResponse]:
        """
        Encodes the ProtoBuf requests into binary form, send them to the endpoint, and returns the resulting responses.

        :param requests: the requests to encode
        :return: the responses from the server
        """
        # Add the header and encode the Protobuf requests
        http_data_req = self.preamble.to_binary()
        for request in requests:
            http_data_req += request.to_binary()

        # Send the HTTP request
        http_request = Request(self.endpoint, data=http_data_req, headers=self.headers, method='POST')
        with urllib.request.urlopen(http_request) as http_response:
            http_response: HTTPResponse
            if http_response.status != 200:
                raise Exception(f'Unexpected HTTP status code, got {http_response.status}, wanted 200')

            http_data_resp = http_response.read()

        # Read the response data
        offset = 0

        resp_preamble = PBResponsePreamble.from_binary(http_data_resp[:2])
        offset += resp_preamble.byte_count

        if resp_preamble.protocol_version != self.preamble.protocol_version:
            raise Exception(
                f'Protocol versions {self.preamble.protocol_version} (Request) and {resp_preamble.protocol_version} (Response) do not match')

        responses: list[PBResponse] = []
        while offset < len(http_data_resp):
            response = PBResponse.from_binary(http_data_resp[offset:])
            offset += response.byte_count
            responses.append(response)

        if offset != len(http_data_resp):
            print(f'Warning: Unread bytes at the end: offset {offset} len {len(http_data_resp)}')

        return responses
