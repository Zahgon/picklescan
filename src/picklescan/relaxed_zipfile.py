# A more forgiving implementation of zipfile.ZipFile
# Modified from Python code at
# https://github.com/python/cpython/blob/edb69578ed74ff04ab78ab953355faa343a7e0ee/Lib/zipfile/__init__.py#L1606
# Changes: removed flag/password/filename/CRC checks to align better with PyTorch's zip decoding

import struct
import zipfile

_FH_SIGNATURE = 0
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = b"PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)


class RelaxedZipFile(zipfile.ZipFile):
    def open(self, name, mode="r", pwd=None, *, force_zip64=False):
        """Return file-like object for 'name'.

        name is a string for the file name within the ZIP file, or a ZipInfo
        object.

        mode should be 'r' to read a file already in the ZIP file, or 'w' to
        write to a file newly added to the archive.

        pwd is the password to decrypt files (only used for reading).

        When writing, if the file size is not known in advance but may exceed
        2 GiB, pass force_zip64 to use the ZIP64 format, which can handle large
        files.  If the size is known in advance, it is best to pass a ZipInfo
        instance for name, with zinfo.file_size set.
        """
        pass
