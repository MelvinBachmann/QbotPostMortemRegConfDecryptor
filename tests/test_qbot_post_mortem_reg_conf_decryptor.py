import pytest
from qbot_post_mortem_reg_conf_decryptor import QbotConfDecryptor, QbotDecryptedConfValue
from regipy import RegistryHive, NKRecord, RegistryKeyNotFoundException


class TestInstance:
    @staticmethod
    def test_instance_type(qbot_decryptor) -> None:
        """Test if instatiating is without trouble and of expected type"""
        assert isinstance(qbot_decryptor, QbotConfDecryptor)


class TestMethods:
    @staticmethod
    def test_validate(qbot_decryptor) -> None:
        """Test the private function "_validate" if it validates the passwords correctly"""
        correct_pw: str = "PC-ABCD12345USER"
        incorrect_pw: str = "pc-abcd12345user"
        assert qbot_decryptor._validate(correct_pw) == correct_pw
        with pytest.raises(ValueError):
            qbot_decryptor._validate(incorrect_pw)

    @staticmethod
    def test_crc32(qbot_decryptor) -> None:
        """
        Test the private function "calc_crc32_shift4", if it calculates checksum correctly
        The function required a byte stream of an utf16-le encoded string.
        For the character t, it's b't00' or 0x0074. Therefore it calculates the crc for the byte 0x74 and based on this crc it calculates the crc on 00. To test the function, we want to test only for 0x74 or for the bytestream b't'.
        When we calculate the crc for "t" on [1], using 0x04C11DB7 as the polynomial and 0xffffffff as the initial value, it results in 0x856A5AA8.
        So we test the function with the bytestream b't' and this should result in decimal value 2238339752 (0x856A5AA8).

        [1] http://www.sunshine2k.de/coding/javascript/crc/crc_js.html
        """
        data: bytes = b"t"
        seed = 0 #initital value = 0xffffffff
        crc32 = qbot_decryptor._crc32(data,0)
        assert crc32 == 2238339752

    @staticmethod
    def test_encode_string(qbot_decryptor) -> None:
        """
        Test if the function "_encode_string" correctly encodes a string and cuts off the BOM signature.
        """
        data = "t"
        data_enc = qbot_decryptor._encode_string(data)
        assert isinstance(data_enc, bytes)
        assert data_enc == b"t\x00"

    @staticmethod
    def test_get_reg_values(qbot_decryptor) -> None:
        """
        Test if a registry key's values is successfully obtained.
        Test if the loaded values contain effectively a sample of known values and test if the length of loaded values is as expected = 8.
        """
        values = qbot_decryptor._get_reg_values(qbot_decryptor.reg_encrypted_conf)
        known_value_names: list = ["d833eaad", "2a593270"]
        assert isinstance(values, dict)
        assert len(values) == 8

    @staticmethod
    def test_gen_reg_val_names_lookup_table(qbot_decryptor) -> None:
        """
        The loaded registry key, should have values and all value names should be in this lookuptable.
        """
        pw = "DESKTOP-R63IG0D1324725303WINI"
        values = qbot_decryptor._get_reg_values(qbot_decryptor.reg_encrypted_conf)
        pw_encoded = QbotConfDecryptor._encode_string(pw)
        checksum_pw = qbot_decryptor._crc32(pw_encoded,0)
        lookup_table = qbot_decryptor._gen_reg_val_names_lookup_table(checksum_pw)
        assert all(name in lookup_table for name in values.keys())

    @staticmethod
    def test_fix_data_format(qbot_decryptor) -> None:
        """test if wrong datatypes are correctly formated into byte stream"""
        dataset = {
                "good_type": b"\x02\xdf\x9d\x98",
                "bad_type": "e096d6f248db8061285b302791",
                }
        dataset_fixed = qbot_decryptor._fix_data_format(dataset)
        assert all(isinstance(data_value, bytes) for data_value in dataset_fixed.values())

    @staticmethod
    def test_fix_data_format_unsupported_type(qbot_decryptor) -> None:
        """test if wrong datatypes are correctly formated into byte stream"""
        dataset = {
                "good_type": b"\x02\xdf\x9d\x98",
                "bad_type": "e096d6f248db8061285b302791",
                "unsupported_type": 12,
                }
        with pytest.raises(TypeError):
            dataset_fixed = qbot_decryptor._fix_data_format(dataset)

    @staticmethod
    def test_truncate_str(qbot_decryptor) -> None:
        """Test the function "truncate_str" if it works as expected"""
        long_string = "kdskslfjsaldkfjddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        if len(long_string) > 10:
            trunc_string = qbot_decryptor.truncate_str(long_string, 10)
            assert len(trunc_string) < 14  # due to the additionla payload added

    @staticmethod
    def test_decrypt_conf(qbot_decryptor) -> None:
        """
        Test the function decrypt_conf, if it successfully decrypts a qbot config.
        Beacause the test registry data is from a sample based on campaign id BB22. We can test for this substring.
        """
        decrypted_conf = qbot_decryptor._decrypt_conf()
        assert isinstance(decrypted_conf, list)
        assert all(isinstance(item, QbotDecryptedConfValue) for item in decrypted_conf)
        flag = False
        for decrypted_val in decrypted_conf:
            if "BB22" in decrypted_val.decrypted_data:
                flag = True
        assert flag


class TestAttrs:
    @staticmethod
    def test_hive(qbot_decryptor) -> None:
        """Test if the attr "hive" is correctly loaded and the returned type is correct"""
        hive = qbot_decryptor.hive
        assert isinstance(hive, RegistryHive)

    @staticmethod
    def test_hive_wrong_hive_path(qbot_decryptor_wrong_hivepath) -> None:
        """Test if exception is handled when a wrong hive path is provided"""
        with pytest.raises(FileNotFoundError):
            hive = qbot_decryptor_wrong_hivepath.hive

    @staticmethod
    def test_reg_encrypted_conf(qbot_decryptor) -> None:
        """Test if the attr "reg_encrypted_conf" is correctly loaded and the returned type is as expected"""
        encrypted_config = qbot_decryptor.reg_encrypted_conf
        print(encrypted_config)
        assert isinstance(encrypted_config, NKRecord)

    @staticmethod
    def test_reg_encrypted_conf_wrong_key(qbot_decryptor_wrong_key) -> None:
        """Test if exception is handled when a non existing key is provided"""
        with pytest.raises(RegistryKeyNotFoundException):
            encrypted_config = qbot_decryptor_wrong_key.reg_encrypted_conf

    @staticmethod
    def test_decrypted_conf(qbot_decryptor) -> None:
        """Test if the attr "decrypted_conf" is correctly loaded and the returned type is as expected"""
        decrypted_conf = qbot_decryptor.decrypted_conf
        assert isinstance(decrypted_conf, list)
        assert all(isinstance(item, QbotDecryptedConfValue) for item in decrypted_conf)
