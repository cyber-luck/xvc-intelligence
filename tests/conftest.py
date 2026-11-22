import os
from pathlib import Path

import pytest

from xvcintel.core.reader import BytesSource, FileSource
from xvcintel.core.result import Ok
from xvcintel.engines.package import load_package

import synthxvc

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def synth():
    return synthxvc.build()


@pytest.fixture(scope="session")
def synth_pkg(synth):
    r = load_package(BytesSource(synth.data, "sintetico.xvc"))
    assert isinstance(r, Ok), r
    return r.value


@pytest.fixture(scope="session")
def synth_file(tmp_path_factory, synth):
    p = tmp_path_factory.mktemp("pkg") / "sintetico.xvc"
    p.write_bytes(synth.data)
    return p


@pytest.fixture(scope="session")
def fixtures_dir():
    return FIX


REAL = os.environ.get("XVC_PATH")


@pytest.fixture(scope="session")
def real_pkg():
    if not REAL or not os.path.exists(REAL):
        pytest.skip("XVC_PATH nao definido: teste de integracao com o pacote real pulado")
    src = FileSource(REAL)
    r = load_package(src)
    assert isinstance(r, Ok), r
    yield r.value
    src.close()
