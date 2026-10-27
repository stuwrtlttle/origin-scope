import tarfile
import tempfile
import unittest
from pathlib import Path

import package_vexscope


class PackageVexScopeTests(unittest.TestCase):
    def test_bundle_contains_exactly_the_runtime_files(self):
        source_dir = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            archive_path = package_vexscope.build_archive(
                Path(directory) / "vexscope-bundle.tar.gz", source_dir
            )
            with tarfile.open(archive_path, "r:gz") as archive:
                names = sorted(member.name for member in archive.getmembers() if member.isfile())

        self.assertEqual(
            names,
            sorted(f"{package_vexscope.BUNDLE_DIRECTORY}/{name}" for name in package_vexscope.RUNTIME_FILES),
        )

    def test_bundle_fails_when_a_runtime_file_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(FileNotFoundError, "vexscope_app.py"):
                package_vexscope.build_archive(Path(directory) / "bundle.tar.gz", directory)


if __name__ == "__main__":
    unittest.main()
