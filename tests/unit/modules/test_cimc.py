"""
tests.unit.modules.test_cimc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the cimc module
"""

import logging

import salt.modules.cimc as cimc_module
from salt.exceptions import CommandExecutionError
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.mock import MagicMock, patch
from tests.support.unit import TestCase

log = logging.getLogger(__name__)


CERTIFICATE_UPLOAD_RESPONSE = {
    "outConfig": {
        "uploadExternalCertificate": {
            "dn": "sys/cert-mgmt/external-cert-upload",
            "adminAction": "no-op",
            "uploadStatus": "COMPLETED",
            "uploadProgress": "100%",
            "status": "modified",
        }
    }
}

PRIVATE_KEY_UPLOAD_RESPONSE = {
    "outConfig": {
        "uploadExternalPrivateKey": {
            "dn": "sys/cert-mgmt/external-pvt-key-upload",
            "adminAction": "no-op",
            "uploadStatus": "COMPLETED",
            "uploadProgress": "100%",
            "status": "modified",
        }
    }
}

ACTIVATE_CERT_RESPONSE = {
    "outConfig": {
        "certificateManagement": {
            "dn": "sys/cert-mgmt",
            "description": "Certificate Management",
            "adminAction": "no-op",
            "status": "modified",
        }
    }
}

SAMPLE_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcm9teleQFkF2Ri1PNLRi
SAMPLE_CERT_DATA_HERE
-----END CERTIFICATE-----"""

SAMPLE_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
SAMPLE_KEY_DATA_HERE
-----END RSA PRIVATE KEY-----"""


class CIMCModuleTestCase(TestCase, LoaderModuleMockMixin):
    """Test cases for salt.modules.cimc"""

    def setup_loader_modules(self):
        return {
            cimc_module: {
                "__proxy__": {
                    "cimc.set_config_modify": MagicMock(
                        return_value=CERTIFICATE_UPLOAD_RESPONSE
                    )
                }
            }
        }

    def test_upload_external_certificate_success(self):
        """Test successful certificate upload"""
        with patch.dict(
            cimc_module.__proxy__,
            {"cimc.set_config_modify": MagicMock(return_value=CERTIFICATE_UPLOAD_RESPONSE)},
        ):
            result = cimc_module.upload_external_certificate(SAMPLE_CERTIFICATE)
            self.assertEqual(
                result["outConfig"]["uploadExternalCertificate"]["uploadStatus"],
                "COMPLETED",
            )

    def test_upload_external_certificate_no_certificate(self):
        """Test certificate upload with no certificate provided"""
        with self.assertRaises(CommandExecutionError) as context:
            cimc_module.upload_external_certificate(None)
        self.assertIn("certificate must be specified", str(context.exception))

    def test_upload_external_certificate_empty_certificate(self):
        """Test certificate upload with empty certificate"""
        with self.assertRaises(CommandExecutionError) as context:
            cimc_module.upload_external_certificate("")
        self.assertIn("certificate must be specified", str(context.exception))

    def test_upload_external_certificate_xml_escaping(self):
        """Test that XML special characters are properly escaped"""
        malicious_cert = '-----BEGIN CERTIFICATE-----\n<malicious>&"test"</malicious>\n-----END CERTIFICATE-----'
        mock_set_config = MagicMock(return_value=CERTIFICATE_UPLOAD_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.upload_external_certificate(malicious_cert)

            # Verify the function was called
            mock_set_config.assert_called_once()

            # Get the inconfig argument
            call_args = mock_set_config.call_args
            inconfig = call_args[0][1]

            # Verify XML special characters are escaped
            self.assertIn("&lt;malicious&gt;", inconfig)
            self.assertIn("&amp;", inconfig)
            self.assertIn("&quot;", inconfig)
            self.assertNotIn("<malicious>", inconfig)

    def test_upload_external_private_key_success(self):
        """Test successful private key upload"""
        with patch.dict(
            cimc_module.__proxy__,
            {"cimc.set_config_modify": MagicMock(return_value=PRIVATE_KEY_UPLOAD_RESPONSE)},
        ):
            result = cimc_module.upload_external_private_key(SAMPLE_PRIVATE_KEY)
            self.assertEqual(
                result["outConfig"]["uploadExternalPrivateKey"]["uploadStatus"],
                "COMPLETED",
            )

    def test_upload_external_private_key_no_key(self):
        """Test private key upload with no key provided"""
        with self.assertRaises(CommandExecutionError) as context:
            cimc_module.upload_external_private_key(None)
        self.assertIn("key must be specified", str(context.exception))

    def test_upload_external_private_key_empty_key(self):
        """Test private key upload with empty key"""
        with self.assertRaises(CommandExecutionError) as context:
            cimc_module.upload_external_private_key("")
        self.assertIn("key must be specified", str(context.exception))

    def test_upload_external_private_key_xml_escaping(self):
        """Test that XML special characters are properly escaped in private key"""
        malicious_key = '-----BEGIN RSA PRIVATE KEY-----\n<script>&"injection"</script>\n-----END RSA PRIVATE KEY-----'
        mock_set_config = MagicMock(return_value=PRIVATE_KEY_UPLOAD_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.upload_external_private_key(malicious_key)

            # Verify the function was called
            mock_set_config.assert_called_once()

            # Get the inconfig argument
            call_args = mock_set_config.call_args
            inconfig = call_args[0][1]

            # Verify XML special characters are escaped
            self.assertIn("&lt;script&gt;", inconfig)
            self.assertIn("&amp;", inconfig)
            self.assertIn("&quot;", inconfig)
            self.assertNotIn("<script>", inconfig)

    def test_activate_external_certificate_success(self):
        """Test successful certificate activation"""
        with patch.dict(
            cimc_module.__proxy__,
            {"cimc.set_config_modify": MagicMock(return_value=ACTIVATE_CERT_RESPONSE)},
        ):
            result = cimc_module.activate_external_certificate()
            self.assertEqual(
                result["outConfig"]["certificateManagement"]["status"],
                "modified",
            )

    def test_upload_external_certificate_correct_dn(self):
        """Test that certificate upload uses correct DN"""
        mock_set_config = MagicMock(return_value=CERTIFICATE_UPLOAD_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.upload_external_certificate(SAMPLE_CERTIFICATE)

            call_args = mock_set_config.call_args
            dn = call_args[0][0]
            self.assertEqual(dn, "sys/cert-mgmt/external-cert-upload")

    def test_upload_external_private_key_correct_dn(self):
        """Test that private key upload uses correct DN"""
        mock_set_config = MagicMock(return_value=PRIVATE_KEY_UPLOAD_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.upload_external_private_key(SAMPLE_PRIVATE_KEY)

            call_args = mock_set_config.call_args
            dn = call_args[0][0]
            self.assertEqual(dn, "sys/cert-mgmt/external-pvt-key-upload")

    def test_activate_external_certificate_correct_dn(self):
        """Test that certificate activation uses correct DN"""
        mock_set_config = MagicMock(return_value=ACTIVATE_CERT_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.activate_external_certificate()

            call_args = mock_set_config.call_args
            dn = call_args[0][0]
            self.assertEqual(dn, "sys/cert-mgmt")

    def test_upload_external_certificate_admin_action(self):
        """Test that certificate upload uses content-cert-upload admin action"""
        mock_set_config = MagicMock(return_value=CERTIFICATE_UPLOAD_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.upload_external_certificate(SAMPLE_CERTIFICATE)

            call_args = mock_set_config.call_args
            inconfig = call_args[0][1]
            self.assertIn('adminAction="content-cert-upload"', inconfig)

    def test_upload_external_private_key_admin_action(self):
        """Test that private key upload uses content-cert-upload admin action"""
        mock_set_config = MagicMock(return_value=PRIVATE_KEY_UPLOAD_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.upload_external_private_key(SAMPLE_PRIVATE_KEY)

            call_args = mock_set_config.call_args
            inconfig = call_args[0][1]
            self.assertIn('adminAction="content-cert-upload"', inconfig)

    def test_activate_external_certificate_admin_action(self):
        """Test that certificate activation uses activate-external-cert admin action"""
        mock_set_config = MagicMock(return_value=ACTIVATE_CERT_RESPONSE)

        with patch.dict(cimc_module.__proxy__, {"cimc.set_config_modify": mock_set_config}):
            cimc_module.activate_external_certificate()

            call_args = mock_set_config.call_args
            inconfig = call_args[0][1]
            self.assertIn('adminAction="activate-external-cert"', inconfig)
