import sys
import pytest
from qbot_post_mortem_reg_conf_decryptor import QbotConfDecryptor


@pytest.fixture
def qbot_decryptor() -> QbotConfDecryptor:
    """
    Returns an instance of the qbot decryptor class
    """
    return QbotConfDecryptor(
            hivepath="./tests/testdata/532800b423fecbca1ad9934d4f0101c31018f3d34031ffc4107d4ea5763a2a3f/lab/NTUSER_wini.DAT",
            registry_key="ROOT\SOFTWARE\Microsoft\Hlimyemzintup",
            password="DESKTOP-R63IG0D1324725303WINI"
            )

@pytest.fixture
def qbot_decryptor_wrong_hivepath() -> QbotConfDecryptor:
    """
    Returns an instance of the qbot decryptor class
    """
    return QbotConfDecryptor(
            hivepath="./tests/testdata/nonexist.dat",
            registry_key="ROOT\SOFTWARE\Microsoft\Hlimyemzintup",
            password="DESKTOP-R63IG0D1324725303WINI"
            )

@pytest.fixture
def qbot_decryptor_wrong_key() -> QbotConfDecryptor:
    """
    Returns an instance of the qbot decryptor class
    """
    return QbotConfDecryptor(
            hivepath="./tests/testdata/532800b423fecbca1ad9934d4f0101c31018f3d34031ffc4107d4ea5763a2a3f/lab/NTUSER_wini.DAT",
            registry_key="ROOT\SOFTWARE\Microsoft\nonexist",
            password="DESKTOP-R63IG0D1324725303WINI"
            )
