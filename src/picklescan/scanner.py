from dataclasses import dataclass, field
from enum import Enum
import http.client
import io
import json
import logging
import os
import pickletools
import re
from tarfile import TarError
from tempfile import TemporaryDirectory
from typing import IO, List, Optional, Set, Tuple
import urllib.parse
import zipfile
from .relaxed_zipfile import RelaxedZipFile

from .torch import (
    get_magic_number,
    InvalidMagicError,
    _is_zipfile,
    MAGIC_NUMBER,
    _should_read_directly,
)


class SafetyLevel(Enum):
    Innocuous = "innocuous"
    Suspicious = "suspicious"
    Dangerous = "dangerous"


@dataclass
class Global:
    module: str
    name: str
    safety: SafetyLevel


@dataclass
class ScanResult:
    globals: List[Global]
    scanned_files: int = 0
    issues_count: int = 0
    infected_files: int = 0
    scan_err: bool = False

    def merge(self, sr: "ScanResult"):
        pass


@dataclass
class ScanFilter:
    """Filtering options for directory scans, modeled after ClamAV clamscan.

    - ``exclude``: regexes matched against the full file path; matching files are skipped.
    - ``include``: regexes matched against the full file path; when set, only matching files are scanned.
    - ``exclude_dir``: regexes matched against directory paths; matching directories are not traversed.
    - ``include_dir``: regexes matched against directory paths; when set, only matching directories are traversed.

    Excludes always take precedence over includes.
    Multiple patterns of the same kind are combined with logical OR.
    """

    exclude: List[re.Pattern] = field(default_factory=list)
    include: List[re.Pattern] = field(default_factory=list)
    exclude_dir: List[re.Pattern] = field(default_factory=list)
    include_dir: List[re.Pattern] = field(default_factory=list)


class GenOpsError(Exception):
    def __init__(self, msg: str, globals: Optional[Set[Tuple[str, str]]]):
        self.msg = msg
        self.globals = globals
        super().__init__()

    def __str__(self) -> str:
        return self.msg


_log = logging.getLogger("picklescan")

_safe_globals = {
    "collections": {"OrderedDict"},
    "torch": {
        "LongStorage",
        "FloatStorage",
        "HalfStorage",
        "QUInt2x4Storage",
        "QUInt4x2Storage",
        "QInt32Storage",
        "QInt8Storage",
        "QUInt8Storage",
        "ComplexFloatStorage",
        "ComplexDoubleStorage",
        "DoubleStorage",
        "BFloat16Storage",
        "BoolStorage",
        "CharStorage",
        "ShortStorage",
        "IntStorage",
        "ByteStorage",
    },
    "numpy": {
        "dtype",
        "ndarray",
    },
    "numpy._core.multiarray": {
        "_reconstruct",
    },
    "numpy.core.multiarray": {
        "_reconstruct",
    },
    "torch._utils": {"_rebuild_tensor_v2"},
}

_unsafe_globals = {
    "__builtin__": {
        # Pickle versions 0, 1, 2 have those function under '__builtin__'
        "eval",
        "compile",
        "getattr",
        "apply",
        "exec",
        "open",
        "breakpoint",
    },
    "builtins": {
        # Pickle versions 3, 4 have those function under 'builtins'
        "eval",
        "compile",
        "getattr",
        "apply",
        "exec",
        "open",
        "breakpoint",
    },
    # cloudpickle can reconstruct arbitrary callables via CodeType, enabling code execution
    "cloudpickle.cloudpickle": {
        "_builtin_type",  # Used to access CodeType for arbitrary code construction
        "_make_function",  # Creates functions from code objects
        "_function_setstate",  # Sets internal function state
        "_make_cell",  # Creates closure cells
        "_make_empty_cell",  # Creates empty closure cells
        "subimport",  # Imports arbitrary modules
    },
    "types": {"CodeType"},  # Can construct arbitrary code objects for execution
    "aiohttp": "*",
    "asyncio": "*",
    "bdb": "*",
    "commands": "*",  # Python 2 precursor to subprocess
    "ctypes": "*",  # Foreign function interface, can load DLLs, call C functions, manipulate raw memory
    "functools": "partial",  # functools.partial(os.system, "echo pwned")
    "httplib": "*",  # Includes http.client.HTTPSConnection()
    "logging": {"FileHandler"},  # logging.FileHandler can create arbitrary files on the filesystem
    "_io": {"FileIO"},  # io.FileIO is stored as _io.FileIO, can read arbitrary files bypassing builtins.open blocklist
    "numpy.f2py": "*",  # Multiple unsafe functions (e.g., getlincoef, _eval_length) that call eval on arbitrary strings
    "numpy.testing._private.utils": "*",  # runstring() in this module is a synonym for exec()
    "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
    "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
    "_operator": {
        "attrgetter",  # Ex of code execution: operator.attrgetter("system")(__import__("os"))("echo pwned")
        "itemgetter",
        "methodcaller",
    },
    "operator": {
        "attrgetter",  # Ex of code execution: operator.attrgetter("system")(__import__("os"))("echo pwned")
        "itemgetter",
        "methodcaller",
    },
    "os": "*",
    "requests.api": "*",
    "runpy": "*",  # Includes runpy._run_code
    "shutil": "*",
    "socket": "*",
    "ssl": "*",  # DNS exfiltration via ssl.get_server_certificate()
    "subprocess": "*",
    "sys": "*",
    "code": {"InteractiveInterpreter.runcode"},
    "cProfile": "*",  # cProfile.run() and cProfile.runctx() call exec() on arbitrary strings
    "distutils.file_util": "*",  # arbitrary file write via distutils.file_util.write_file()
    "doctest": {"debug_script"},
    "ensurepip": {"_run_pip"},
    "idlelib.autocomplete": {"AutoComplete.get_entity", "AutoComplete.fetch_completions"},
    "idlelib.calltip": {"Calltip.fetch_tip", "get_entity"},
    "idlelib.debugobj": {"ObjectTreeItem.SetText"},
    "idlelib.pyshell": {"ModifiedInterpreter.runcode", "ModifiedInterpreter.runcommand"},
    "idlelib.run": {"Executive.runcode"},
    "imaplib": {"IMAP4_stream"},  # IMAP4_stream executes commands via subprocess.Popen(command, shell=True)
    "lib2to3.pgen2.grammar": {"Grammar.loads"},
    "lib2to3.pgen2.pgen": {"ParserGenerator.make_label"},
    "pdb": "*",
    "pickle": "*",
    "_pickle": "*",
    "pip": "*",
    "pkgutil": {"resolve_name"},  # pkgutil.resolve_name can resolve any module:attribute, bypassing the entire blocklist
    "pty": "*",  # pty.spawn() allows executing arbitrary commands
    "profile": "*",  # profile.run() and profile.runctx() call exec() on arbitrary strings
    "pydoc": "*",  # pydoc.locate can import arbitrary modules, pydoc.pipepager allows command execution
    "test": "*",  # test.support.script_helper.assert_python_ok spawns arbitrary python subprocesses
    "timeit": "*",
    "torch._dynamo.guards": {"GuardBuilder.get"},
    "torch._inductor.codecache": "compile_file",  # compile_file('', '', ['sh', '-c','$(echo pwned)'])
    "torch.fx.experimental.symbolic_shapes": {"ShapeEnv.evaluate_guards_expression"},
    "torch.jit.unsupported_tensor_ops": {"execWrapper"},
    "torch.serialization": "load",  # pickle could be used to load a different file
    "torch.utils._config_module": {
        "ConfigModule.load_config"
    },  # allows storing a pickle inside a pickle (if this has valid use cases, scan the input bytes instead of flagging the global)
    "torch.utils.bottleneck.__main__": {"run_cprofile", "run_autograd_prof"},
    "torch.utils.collect_env": {"run"},
    "torch.utils.data.datapipes.utils.decoder": {
        "basichandlers"
    },  # allows storing a pickle inside a pickle (if this has valid use cases, scan the input bytes instead of flagging the global)
    "trace": {"Trace.run", "Trace.runctx"},
    "urllib.request": "*",  # urllib.request.urlopen can be used for SSRF and data exfiltration
    "uuid": "*",  # uuid._get_command_stdout executes arbitrary commands via subprocess.Popen
    "venv": "*",
    "webbrowser": "*",  # Includes webbrowser.open()
    "_osx_support": "*",  # _read_output and _find_build_tool execute commands via os.system
    "_aix_support": "*",  # _read_cmd_output executes commands via os.system
    "_pyrepl": "*",  # _pyrepl.pager.pipe_pager/tempfile_pager execute commands via subprocess/os.system
}

#
# TODO: handle methods loading other Pickle files (either mark as suspicious, or follow calls to scan other files [preventing infinite loops])
#
# numpy.load()
# https://numpy.org/doc/stable/reference/generated/numpy.load.html#numpy.load
# numpy.ctypeslib.load_library()
# https://numpy.org/doc/stable/reference/routines.ctypeslib.html#numpy.ctypeslib.load_library
# pandas.read_pickle()
# https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_pickle.html
# joblib.load()
# https://joblib.readthedocs.io/en/latest/generated/joblib.load.html
# torch.load()
# https://pytorch.org/docs/stable/generated/torch.load.html
# tf.keras.models.load_model()
# https://www.tensorflow.org/api_docs/python/tf/keras/models/load_model
#

_numpy_file_extensions = {".npy"}  # Note: .npz is handled as zip files
_pytorch_file_extensions = {".bin", ".pt", ".pth", ".ckpt"}
_pickle_file_extensions = {".pkl", ".pickle", ".joblib", ".dat", ".data"}
_zip_file_extensions = {".zip", ".npz", ".7z"}
# Pickle files do not actually have magic bytes, but v2+ files
# start with a PROTO (\x80) opcode followed by a byte with the protocol version
_pickle_magic_bytes = {
    b"\x80\x00",
    b"\x80\x01",
    b"\x80\x02",
    b"\x80\x03",
    b"\x80\x04",
    b"\x80\x05",
}
_numpy_magic_bytes = b"\x93NUMPY"


def _is_7z_file(f: IO[bytes]) -> bool:
    pass


def _http_get(url) -> bytes:
    pass


def _list_globals(data: IO[bytes], multiple_pickles=True) -> Set[Tuple[str, str]]:
    pass


def _build_scan_result_from_raw_globals(
    raw_globals: Set[Tuple[str, str]],
    file_id,
    scan_err=False,
) -> ScanResult:
    pass


def scan_pickle_bytes(data: IO[bytes], file_id, multiple_pickles=True) -> ScanResult:
    """Disassemble a Pickle stream and report issues"""
    pass


# XXX: it appears there is not way to get the byte stream for a given file within the 7z archive and thus forcing us to unzip to disk before scanning
def scan_7z_bytes(data: IO[bytes], file_id) -> ScanResult:
    pass


def scan_zip_bytes(data: IO[bytes], file_id) -> ScanResult:
    pass


def scan_numpy(data: IO[bytes], file_id) -> ScanResult:
    pass


def scan_pytorch(data: IO[bytes], file_id) -> ScanResult:
    pass


def scan_bytes(data: IO[bytes], file_id, file_ext: Optional[str] = None) -> ScanResult:
    pass


def scan_huggingface_model(repo_id):
    pass


def _matches_any(patterns: List[re.Pattern], text: str) -> bool:
    """Return True if *text* matches at least one compiled regex in *patterns*."""
    pass


def scan_directory_path(path, scan_filter: Optional[ScanFilter] = None) -> ScanResult:
    pass


def scan_file_path(path) -> ScanResult:
    pass


def scan_url(url) -> ScanResult:
    pass
