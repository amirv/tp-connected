"""Library for interfacing with Tp-Link LTE modems."""
import logging
import re
from functools import wraps
from datetime import datetime
import asyncio
from aiohttp.client_exceptions import ClientError
import async_timeout
import attr
import base64
from .tp_link_encryption import tp_link_encryption

TIMEOUT = 3
LOGIN_TIMEOUT = 300

_LOGGER = logging.getLogger(__name__)

class Error(Exception):
    """Base class for all exceptions."""

def autologin(function, timeout=TIMEOUT, login_timeout=LOGIN_TIMEOUT):
    """Decorator that will try to login and redo an action before failing."""
    @wraps(function)
    async def wrapper(self, *args, **kwargs):
        """Wrap a function with timeout."""
        try:
            async with async_timeout.timeout(timeout):
                return await function(self, *args, **kwargs)
        except (asyncio.TimeoutError, ClientError, Error):
            pass

        _LOGGER.debug("autologin")
        try:
            async with async_timeout.timeout(login_timeout):
                await self.login()
                return await function(self, *args, **kwargs)
        except (asyncio.TimeoutError, ClientError, Error):
            raise Error(str(function))

    return wrapper


@attr.s
class MR6400:
    """Class for Tp-Link MR6400 interface."""

    hostname = attr.ib()
    websession = attr.ib()

    username = attr.ib(default="admin")
    password = attr.ib(default=None)
    token = attr.ib(default=None)

    listeners = attr.ib(init=False, factory=list)
    max_sms_id = attr.ib(init=False, default=None)
    task = attr.ib(init=False, default=None)

    _encryptedUsername = None;
    _encryptedPassword = None;

    @property
    def _baseurl(self):
        return "http://{}/".format(self.hostname)

    def _url(self, path):
        """Build a complete URL for the device."""
        return self._baseurl + path

    async def add_sms_listener(self, listener):
        """Add a listener for new SMS."""
        self.listeners.append(listener)

    async def logout(self):
        """Cleanup resources."""
        self.websession = None
        self.token = None

    async def encryptString(self, value, nn, ee):
        value64 = base64.b64encode(value.encode("utf-8"))
        return tp_link_encryption.enc(value64.decode('UTF-8'), nn, ee)    

    async def encryptCredentials(self, password=None, username=None):
        if password is None:
            password = self.password
        else:
            self.password = password

        if username is None:
            username = self.username
        else:
            self.username = username

        try:
            async with async_timeout.timeout(LOGIN_TIMEOUT):
                url = self._url('cgi/getParm')
                headers= { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, headers=headers) as response:
                    if response.status != 200:
                        _LOGGER.error("Invalid encryption key request")
                        raise Error()
                    responseText = await response.text()
                    eeExp = re.compile(r'(?<=ee=")(.{5}(?:\s|.))', re.IGNORECASE)
                    eeString = eeExp.search(responseText)
                    if eeString:
                        ee = eeString.group(1) 
                    nnExp = re.compile(r'(?<=nn=")(.{255}(?:\s|.))', re.IGNORECASE)
                    nnString = nnExp.search(responseText)
                    if nnString:
                        nn = nnString.group(1)   
        except (asyncio.TimeoutError, ClientError, Error):
            raise Error("Could not retrieve encryption key")
        
        _LOGGER.debug("ee: {0} nn: {1}".format(ee, nn))  
        
        self._encryptedUsername = await self.encryptString(username, nn, ee)
        _LOGGER.debug("Encrypted username: {0}".format(self._encryptedUsername))

        self._encryptedPassword = await self.encryptString(password, nn, ee)
        _LOGGER.debug("Encrypted password: {0}".format(self._encryptedPassword))

        # TODO: without this sleep there's a strange behaviour in the following network request.
        # I need to understand if the problem is caused by the router or the aiohttp API
        await asyncio.sleep(1)

    
    async def login(self, password=None, username=None):
        try:
            """Create a session with the modem and update the token id."""
            await self.encryptCredentials(password, username)
            async with async_timeout.timeout(LOGIN_TIMEOUT):
                url = self._url('cgi/login')
                params = {'UserName': self._encryptedUsername, 'Passwd': self._encryptedPassword, 'Action': '1', 'LoginStatus':'0' }
                headers= { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, params=params, headers=headers) as response:
                    if response.status != 200:
                        _LOGGER.error("Invalid login request")
                        raise Error()
                    hasSessionId = False
                    for cookie in self.websession.cookie_jar:
                        if cookie["domain"] == self.hostname and cookie.key == 'JSESSIONID':
                            hasSessionId = True
                            _LOGGER.debug("Session id: %s", cookie.value)
                    if not hasSessionId:
                        raise Error("Inavalid credentials")

                await self.getToken()

        except (asyncio.TimeoutError, ClientError, Error):
            raise Error("Could not login")

    async def getToken(self):
        try:
            async with async_timeout.timeout(LOGIN_TIMEOUT):
                url = self._url('')
                _LOGGER.info("Token url %s", url)
                async with self.websession.get(url) as response:
                    if response.status != 200:
                        _LOGGER.error("Invalid token request")
                        raise Error()
                    else:
                        _LOGGER.debug("Valid token request")
                    # parse the html response to find the token
                    responseText = await response.text()
                    p = re.compile(r'(?<=token=")(.{29}(?:\s|.))', re.IGNORECASE)
                    m = p.search(responseText)
                    if m:
                        _LOGGER.debug("Token id: %s", m.group(1) )
                        self.token = m.group(1) 
        

        except (asyncio.TimeoutError, ClientError, Error):
            raise Error("Could not retrieve token")

    @autologin
    async def sms(self, phone, message):
        """Send a message."""
        _LOGGER.debug("Send to %s via %s len=%d",
                      phone, self._baseurl, len(message))

        url = self._url('cgi')
        params = { '2': '' }
        data = "[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={0}\r\ntextContent={1}\r\n".format(phone, message)
        headers= { 'Referer': self._baseurl, 'TokenID': self.token }
        async with self.websession.post(url, params=params, data=data, headers=headers) as response:
            _LOGGER.debug("Sent message with status %d", response.status)
            if response.status != 200:
                raise Error("Failed sending SMS")


class Modem(MR6400):
    """Class for any modem."""
