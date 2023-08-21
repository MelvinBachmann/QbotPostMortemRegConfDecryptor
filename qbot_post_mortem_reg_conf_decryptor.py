import argparse
from dataclasses import dataclass
from typing import Optional
from hashlib import sha1
from struct import pack
from regipy.registry import (  # type: ignore
        RegistryHive,
        NKRecord,
        RegistryKeyNotFoundException,
        )
from Crypto.Cipher import ARC4
from hexdump import hexdump  # type: ignore


@dataclass
class QbotDecryptedConfValue:
    """
    Description:
        Manager class for decrypted registry values (qbot conf) with
        its metadata.

    Attribues:
        - reg_val(str): Value which has been decrypted.
        - rc4_key(str): Rc4 key which has been used for decryption.
        - decrypted_data(str): Decrypted key value (part of qbot conf)
    """
    reg_val: str
    rc4_key: str
    decrypted_data: str


class QbotConfDecryptor:
    """
    Description:
        Functions and attributes for decryption process of
        QBot configuration in registry hive.

        Decryption tested on the following campaing id's:
            * BB22
            * obama271

    Attributes:
        - hive(RegistryHive): Registry hive object for the loaded hive
        file passed to the constructor.

    Methods:
        - __init__(self): Constructor
        - _validate(password: str): Validates if the password is in upper case
        only.
        - _crc32(self, data: bytes, seed: int): Calculates a crc32 checksum for
        a given datastream and seed. Seed = 0 = common initial value = 0xffffffff.
        - _encode_string(data: str): Encodes string as utf-16le an cuts off a
        possible BOM signature.
        - _gen_reg_val_names_lookup_table(self, checksum_pw: str): Generates a
        lookuptable for all possible value names, related to crc32 checksum of
        the password.
        - _get_reg_values(key: NKRecord): Obtain values of an registry key object.
        - _fix_data_format(data: dict): Fixes the type of value data, when it is
        returned as a string instead of bytes by RegistryHive class.
        - truncate_str(string: str, max_length: int = 100): Globally accessable
        function to truncate the decrypted output. Sometimes nice to have, when
        a config value is very long and fills up the console buffer.
        - _decrypt_conf(self): Final decryption of qbot config in registry.
    """

    def __init__(self,
            hivepath: str,
            registry_key: str,
            password: str,
            excluded_values: Optional[list[str]] = None,
            ) -> None:
        self.hivepath = hivepath
        self.reg_key = registry_key
        self.password = self._validate(password)
        self._hive: Optional[RegistryHive] = None
        self._reg_encrypted_conf: Optional[NKRecord] = None
        self._decrypted_conf: Optional[list[QbotDecryptedConfValue]] = None
        self._excluded_values = excluded_values

    @property
    def hive(self) -> RegistryHive:
        """
        Description:
            Global accessable attribute to a registry hive object.
            Points to the hive file which is passed to the constructor.

        Returns:
            - RegistryHive: RegistryHive object for the hive file passed to the
            constructor.

        Raises:
            - TypeError: Handles the error, when a wrong type is passed to the
            RegistryHive class (e.g. When a NoneType is passed). This should
            only occur due to programing issues.
            - FileNotFoundError: Handles the error, when a non existing hive
            has been provided. Such mistakes are expected when using the
            framework.
        """
        if not self._hive:
            try:
                self._hive = RegistryHive(self.hivepath)
            except TypeError as e:
                raise TypeError("The provided path to the hive file is not of "\
                        "expected type str, bytes, os.Path like: "\
                        f"{type(self._hive)!r}"\
                        f"\nError: {str(e)}") from e
            except FileNotFoundError as e:
                raise FileNotFoundError("The provided file can not be found: "\
                        f"{self.hivepath!r}") from e

        return self._hive

    @property
    def reg_encrypted_conf(self) -> NKRecord:
        """
        Description:
            Global accessable attribute to a NKRecord object.
            It is a handle to the registry key, where the qbot config
            is located.

        Returns:
            - NKRecord: NKRecord object for the key, where the qbot config is
            located.

        Raises:
            - RegistryKeyNotFoundException: Handles the error when a provided
            key has not been found in hive.
        """
        if not self._reg_encrypted_conf:
            try:
                self._reg_encrypted_conf = self.hive.get_key(self.reg_key)
            except RegistryKeyNotFoundException as e:
                raise RegistryKeyNotFoundException("The provided key does not "\
                        f"exist: {self.reg_key}") from e

        return self._reg_encrypted_conf

    @property
    def decrypted_conf(self) -> list[QbotDecryptedConfValue]:
        """
        Description:
            Global accessable attribute to the decrypted qbot config.
            The decrypted qbot config is returned in form of a list,
            where each item is a decrypted value of qbot config in regsitry.
            This with attributes like registry value path, rc4 for decryption is
            encapsulated in an object QbotDecryptedConfValue.

        Returns:
            - list[ObotDecryptedConfValue]: list of decrypted registry value
            along with metadata (rc4, registry value path).
        """
        if not self._decrypted_conf:
            self._decrypted_conf = self._decrypt_conf()

        return self._decrypted_conf

    @staticmethod
    def _validate(password: str) -> str:
        """
        Description:
            Validates if the password is in uppercase.

        Returns:
            - str: if password is in uppercase, it returns the same password
            string.

        Raises:
            - ValueError: If password is not in uppercase.
        """
        if password.isupper():
            return password

        raise ValueError(f"Only upper case password expected: {password!r}")

    @staticmethod
    def _crc32(data: bytes, seed: int) -> int:
        """
        Description:
            Calculates a crc32 checksum using a the lookup table
            "lookup_table_4bit", bitwise XOR-Operation and Shift 4.

            * lookup_table_4bit: precomputed values for polynomial "0x04C11DB7"
            and all possible 4bit value (nibbles) -> used for efficiency.
            * initial_value: seed = 0 = initial_value = 0xFFFFFFFF is a common
            convention, but the initial_value can be manipulated with a seed.

        Parameters:
            - data(bytes): A byte stream, which represents utf-16 encoded
            characters.
            - seed(int): Seed for salting. Use 0 to choose the common
            initial value = 0xffffffff.

        Returns:
            - int: resulted crc32 checksum in decimal format.
        """
        lookup_table_4bit: list = [
                0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
                0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
                0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
                0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
                ]
        initial_value: int = ~seed & 0xffffffff
        for byte in data:
            xor_value = byte ^ initial_value
            lower_nibble = xor_value & 0x0f
            table_index = lower_nibble
            intermediate_result = lookup_table_4bit[table_index] ^ (
                    (xor_value & 0xffffffff) >> 4)
            initial_value = lookup_table_4bit[intermediate_result & 0x0f] ^ (
                    (intermediate_result & 0xffffffff) >> 4)

        return ~initial_value & 0xffffffff

    @staticmethod
    def _encode_string(data: str) -> bytes:
        """
        Description:
            Encodes a given string to utf-16. If the provided string has a BOM
            signature at the beginning, it will cut off this signature.
            When you convert a character into utf-16le within python
            (.encode(utf-16)), it will add a BOM signature at the beginning of
            the string (\\xff\\xfe).

        Parameters:
            - data(str): Data to encode into utf-16.

        Returns:
            - bytes: Returns bytes stream of the utf-16 encoded string.
        """
        data_enc = data.encode('utf-16')
        return data_enc[2:] if data_enc[:2] == b'\xff\xfe' else data_enc

    def _gen_reg_val_names_lookup_table(self, checksum_pw: int) -> dict:
        """
        Description:
            Precalculate 255 possible registry values and returns a dictionary
            containing each possible registry value with it's id.
            A value name is a hexadecimal value of a crc32 checksum from a
            1byte decimal number which is salted by the previous generated
            crc32 checksum value for the password. Using 1byte decimal value
            (0-255), we can generate 256 possible valuenames related to the
            checksum of the used password.

            It's a lookup table for registry value names.

        Parameters:
            - checksum_pw(str): The crc32 checksum of password.

        Returns:
            - dict: Returns each valuename with it's corresponding id.
        """
        reg_val_names: dict = {}
        for i in range(0,0xff):
            reg_val_names[hex(self._crc32(pack('I',i), checksum_pw))[2:]] = i

        return reg_val_names

    @staticmethod
    def _get_reg_values(key: NKRecord) -> dict:
        """
        Description:
            Loads a given registry key, iterates over each value and
            stores it's value/data in a dictionary, which is finally
            being returned

        Parameters:
            - keyname(NKRecord): NKRecord object of a registry key.

        Returns:
            - dict: Returns a dictionary with each valuename as key and it's
            data as value.
        """
        regs = {}
        for val in key.iter_values():
            regs[val.name] = val.value

        return regs

    @staticmethod
    def _fix_data_format(data: dict) -> dict:
        """
        Description:
            RegistryHive class loads the data sometimes as string
            and sometimes as bytes.
            This function checks the type of data for specific values
            and formates it into a byte datastream like b'\x9d\x93\xab' if
            required.

        Parameters:
            - data(dict): A registry value/data structured dict.

        Returns:
            - dict: Returns the same dict, but types converted where required.

        Raises:
            - TypeError: If a datatype in dict, which is not supported.
        """
        fixed_struct = {}
        for value_name, value_data in data.items():
            if isinstance(value_data, str):
                fixed_struct[value_name] = bytes.fromhex(value_data)
            elif isinstance(value_data, bytes):
                fixed_struct[value_name] = value_data
            else:
                raise TypeError(
                        f"Expected type is str, bytes and not {type(data)!r}")

        return fixed_struct

    @staticmethod
    def truncate_str(string: str, max_length: int = 100) -> str:
        """
        Description:
            Truncates a given string to a give maximal lenght.
            If no maximal lenght is given, it will truncate it default
            max length.

        Parameters:
            - string(str): String to truncated
            - max_lenght: Maximal lenght of new string
            (additional payload is excluded).
        Returns:
            - str: Truncated string.
        """
        if len(string) > max_length:
            return string[:max_length] + "..."

        return string

    def _decrypt_conf(self) -> list[QbotDecryptedConfValue]:
        print(f"[Info] Calculate crc32 checksum for {self.password}..")
        checksum_pw: int = self._crc32(self._encode_string(self.password), 0)
        print(f"[Info] Passwords crc32 checksum: {hex(checksum_pw)}")

        print("[Info] Generate lookup table for registry value names..")
        lookup_reg_values: dict = self._gen_reg_val_names_lookup_table(
                checksum_pw)

        print("[Info] Obtain registry value/data related to qbot config..")
        qbot_conf_encrypted_values: dict = self._get_reg_values(
                self.reg_encrypted_conf)

        print("[Info] Check and fix datatypes in qbot decrypted config..")
        qbot_conf_encrypted_values_fixed: dict = self._fix_data_format(
                qbot_conf_encrypted_values)

        if not qbot_conf_encrypted_values_fixed:
            raise ValueError("No registry value/data (qbot config) loaded")

        decrypted_conf: list[QbotDecryptedConfValue] = []
        for value_name,value_data in qbot_conf_encrypted_values_fixed.items():
            if self._excluded_values and value_name in self._excluded_values:
                continue
            salt: int = lookup_reg_values[value_name]
            salted_key: bytes = pack('I', salt) + pack('I', checksum_pw)
            salted_key_hashed: bytes = sha1(salted_key).digest()
            cipher: ARC4.ARC4Cipher = ARC4.new(salted_key_hashed)
            decrypted_data: bytes = cipher.decrypt(value_data)
            reg_val: str = f"{self.reg_key}\\{value_name}"
            rc4_key: str = " ".join(format(x, '02x') for x in salted_key)
            decrypted_data_hex: str = hexdump(
                    decrypted_data,
                    result="return")
            decrypted_conf.append(QbotDecryptedConfValue(
                reg_val,
                rc4_key,
                decrypted_data_hex,
                ))

        return decrypted_conf


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Qbot config decryptor.")
    parser.add_argument(
            "-r",
            "--registry_hive",
            type=str,
            help="Hive file which contains the qbot config (e.g. ./NTUSER.DAT).",
            required=True,
            )
    parser.add_argument(
            "-k",
            "--key",
            type=str,
            help="Key where the qbot config is located \
                    (e.g. ROOT\SOFTWARE\Microsoft\<random_str>).",
            required=True,
            )
    parser.add_argument(
            "-p",
            "--password",
            type=str,
            help="Password for decryption.\nThe password is equal to\
                    <computer_name.upper()> \
                    + <volumes_serialnumber_decimal.upper()> \
                    + <username.upper()>.",
            required=True,
            )
    parser.add_argument(
            "-e",
            "--excluded_values",
            nargs="+",
            help="Exclude value if unencrypted or other reasons.",
            required=False,
            default=None,
            )

    args = parser.parse_args()
    decryptor = QbotConfDecryptor(
            args.registry_hive,
            args.key,
            args.password,
            args.excluded_values
            )

    for conf in decryptor.decrypted_conf:
        print(f"\nDecrypted value: {conf.reg_val!r}")
        print(f"RC4 Key: {conf.rc4_key!r}")
        print(f"Decrypted data:\n{conf.decrypted_data}")
