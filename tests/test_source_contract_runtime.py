import zipfile
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import apkmirror, gplaydl, utils


class SourceContractRuntimeTests(unittest.TestCase):
    def test_aapt2_badging_parses_version_code_and_min_sdk(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "package: name='com.example.app' versionCode='2024701030' "
                "versionName='47.1.3'\n"
                "sdkVersion:'23'\n"
            ),
            stderr="",
        )

        with patch("src.utils._find_aapt2", return_value="/fake/aapt2"),              patch("src.utils.subprocess.run", return_value=completed):
            info = utils._apk_badging(Path("example.apk"))

        self.assertEqual(info["package"], "com.example.app")
        self.assertEqual(info["version"], "47.1.3")
        self.assertEqual(info["version_code"], 2024701030)
        self.assertEqual(info["min_sdk"], 23)

    def test_aapt2_badging_falls_back_to_apkanalyzer_for_min_sdk(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if command[0] == "/fake/aapt2":
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout=(
                        "package: name='com.example.app' versionCode='100' "
                        "versionName='1.0.0'\n"
                    ),
                    stderr="",
                )
            if command[0] == "/fake/apkanalyzer":
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout="28\n",
                    stderr="",
                )
            raise AssertionError(f"unexpected command: {command}")

        with patch("src.utils._find_aapt2", return_value="/fake/aapt2"), \
             patch("src.utils._find_apkanalyzer", return_value="/fake/apkanalyzer"), \
             patch("src.utils._find_aapt", return_value=None), \
             patch("src.utils.subprocess.run", side_effect=fake_run):
            info = utils._apk_badging(Path("example.apk"))

        self.assertEqual(info["package"], "com.example.app")
        self.assertEqual(info["version"], "1.0.0")
        self.assertEqual(info["version_code"], 100)
        self.assertEqual(info["min_sdk"], 28)
        self.assertEqual(
            calls,
            [
                ["/fake/aapt2", "dump", "badging", "example.apk"],
                ["/fake/apkanalyzer", "manifest", "min-sdk", "example.apk"],
            ],
        )

    def test_apkm_is_accepted_when_source_requires_xapk(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "example.apkm"
            artifact.write_bytes(b"not-a-real-apkm")

            with patch("src.utils.check_apk_integrity", return_value=True), \
                 patch("src.utils._artifact_base_apk", return_value=(artifact, None)), \
                 patch(
                     "src.utils._apk_badging",
                     return_value={
                         "package": "com.example.app",
                         "version": "1.0.0",
                         "version_code": 100,
                         "min_sdk": 29,
                     },
                 ):
                valid, reasons = utils.validate_source_artifact(
                    artifact,
                    {
                        "version": "1.0.0",
                        "version_codes": [100],
                        "min_sdk": 29,
                        "apk_file_types": ["XAPK_REQUIRED"],
                    },
                    "com.example.app",
                    "arm64-v8a",
                )

            self.assertTrue(valid, reasons)
            self.assertEqual(reasons, [])

    def test_xapk_is_accepted_when_source_requires_xapk(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "example.xapk"
            artifact.write_bytes(b"not-a-real-xapk")

            with patch("src.utils.check_apk_integrity", return_value=True), \
                 patch("src.utils._artifact_base_apk", return_value=(artifact, None)), \
                 patch(
                     "src.utils._apk_badging",
                     return_value={
                         "package": "com.example.app",
                         "version": "1.0.0",
                         "version_code": 100,
                         "min_sdk": 29,
                     },
                 ):
                valid, reasons = utils.validate_source_artifact(
                    artifact,
                    {
                        "version": "1.0.0",
                        "version_codes": [100],
                        "min_sdk": 29,
                        "apk_file_types": ["XAPK_REQUIRED"],
                    },
                    "com.example.app",
                    "arm64-v8a",
                )

            self.assertTrue(valid, reasons)
            self.assertEqual(reasons, [])

    def test_merged_google_play_apk_is_accepted_for_xapk_contract_only_when_opted_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "usbhotspot-gplaydl.apk"
            artifact.write_bytes(b"not-a-real-apk")

            target = {
                "version": "1.7",
                "version_codes": [7],
                "min_sdk": 21,
                "apk_file_types": ["XAPK_REQUIRED"],
            }

            with patch("src.utils.check_apk_integrity", return_value=True),                  patch("src.utils._artifact_base_apk", return_value=(artifact, None)),                  patch(
                     "src.utils._apk_badging",
                     return_value={
                         "package": "kha.prog.usbhotspot",
                         "version": "1.7",
                         "version_code": 7,
                         "min_sdk": 21,
                     },
                 ):
                valid, reasons = utils.validate_source_artifact(
                    artifact, target, "kha.prog.usbhotspot", "arm64-v8a",
                    allow_merged_play_apk=True,
                )
                self.assertTrue(valid, reasons)

                valid, reasons = utils.validate_source_artifact(
                    artifact, target, "kha.prog.usbhotspot", "arm64-v8a",
                    allow_merged_play_apk=False,
                )
                self.assertFalse(valid)
                self.assertTrue(any("artifact type mismatch" in r for r in reasons))


    def test_google_play_merge_allows_xapk_contract_as_standalone_apk(self):
        calls = []

        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            base = work_dir / "base.apk"
            with zipfile.ZipFile(base, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"placeholder")
                archive.writestr("lib/arm64-v8a/libexample.so", b"native")

            editor = work_dir / "APKEditor.jar"
            editor.write_bytes(b"fake")

            def fake_run(command, **kwargs):
                calls.append(command)
                merged = Path.cwd() / "com.example.app-merged.apk"
                with zipfile.ZipFile(merged, "w") as archive:
                    archive.writestr("lib/arm64-v8a/libexample.so", b"native")
                return subprocess.CompletedProcess(
                    args=command, returncode=0, stdout="", stderr=""
                )

            def fake_validate(*args, **kwargs):
                self.assertTrue(kwargs.get("allow_merged_play_apk"))
                return True, []

            try:
                with patch.dict(
                    "os.environ",
                    {"SOURCE": "example", "ARCH": "arm64-v8a"},
                    clear=False,
                ), patch(
                    "src.gplaydl._apk_version_name", return_value="1.0.0"
                ), patch(
                    "src.gplaydl._download_apkeditor", return_value=editor
                ), patch(
                    "src.gplaydl.subprocess.run", side_effect=fake_run
                ), patch(
                    "src.gplaydl.utils.get_source_supported_targets",
                    return_value=[
                        {
                            "version": "1.0.0",
                            "version_codes": [100],
                            "min_sdk": 21,
                            "apk_file_types": ["XAPK_REQUIRED"],
                        }
                    ],
                ), patch(
                    "src.gplaydl.utils.validate_source_artifact",
                    side_effect=fake_validate,
                ), patch(
                    "src.gplaydl.utils.strip_zip_entries", return_value=None
                ):
                    result = gplaydl._merge_play_splits(
                        [base], work_dir, "com.example.app"
                    )

                self.assertIsNotNone(result)
                self.assertTrue(Path(result).exists())
                self.assertTrue(any(
                    command[:3] == ["java", "-jar", str(editor)]
                    for command in calls
                ))
            finally:
                Path("com.example.app-merged.apk").unlink(missing_ok=True)

    def test_apkm_is_accepted_when_source_allows_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "example.apkm"
            artifact.write_bytes(b"not-a-real-apkm")

            with patch("src.utils.check_apk_integrity", return_value=True), \
                 patch(
                     "src.utils._artifact_base_apk",
                     return_value=(artifact, None),
                 ), \
                 patch(
                     "src.utils._apk_badging",
                     return_value={
                         "package": "com.example.app",
                         "version": "1.0.0",
                         "version_code": 100,
                         "min_sdk": 23,
                     },
                 ):
                valid, reasons = utils.validate_source_artifact(
                    artifact,
                    {
                        "version": "1.0.0",
                        "version_codes": [100],
                        "min_sdk": 23,
                        "apk_file_types": ["APK_REQUIRED"],
                    },
                    "com.example.app",
                    "arm64-v8a",
                )

            self.assertTrue(valid, reasons)
            self.assertEqual(reasons, [])

    def test_apkmirror_stops_after_cloudflare_block(self):
        calls = []

        def blocked_variant(*args, **kwargs):
            calls.append(args[0])
            apkmirror._blocked_by_cloudflare = True
            return None, False

        try:
            with patch.object(
                apkmirror,
                "_get_api_variant_urls",
                return_value=[
                    ("https://example.invalid/variant-1", "1.0.0"),
                    ("https://example.invalid/variant-2", "1.0.0"),
                ],
            ), patch.object(
                apkmirror,
                "_download_from_variant_page",
                side_effect=blocked_variant,
            ), patch.object(
                apkmirror,
                "_get_direct_release_page",
            ) as direct_release:
                result = apkmirror.get_download_link(
                    "1.0.0",
                    "example",
                    {
                        "package": "com.example.app",
                        "type": "APK",
                        "arch": "arm64-v8a",
                        "dpi": "nodpi",
                        "name": "example",
                        "org": "example",
                    },
                    "arm64-v8a",
                )

            self.assertIsNone(result)
            self.assertEqual(len(calls), 1)
            direct_release.assert_not_called()
        finally:
            apkmirror._blocked_by_cloudflare = False


if __name__ == "__main__":
    unittest.main()
