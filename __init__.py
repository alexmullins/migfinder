from typing import List
from collections import namedtuple

from binaryninja import (BinaryReader, BinaryView, PluginCommand, Section,
                         log_info)

MIGSubsystem = namedtuple('MIGSubsystem', 'addr subsystem num_entries ')

class MigFinder(object):
    """
    Searches a programs DATA and CONST sections looking
    for possible Mig Subsytem handler's using data heuristics
    to find them.
    """

    def __init__(self, bv: BinaryView):
        self._bv = bv
        self._br = BinaryReader(bv)

    def find(self) -> List[MIGSubsystem]:
        """
        Find all of the possible MIG Subsystems in the program's
        DATA and CONST sections.
        Returns a list of MIGSubsystem.
        """
        bv = self._bv
        found: List[MIGSubsystem] = list()

        possible_sections: List[Section] = [
            sec for n, sec in bv.sections.items() if "const" in n
        ]
        for section in possible_sections:
            start = section.start
            end = section.end
            for addr in range(start, end, 8):
                migsubsystem = self._is_valid(addr)
                if migsubsystem is not None:
                    found.append(migsubsystem)
        return found

    def _is_valid(self, addr) -> bool:
        bv = self._bv
        br = self._br
        br.seek(addr)
        # 1. check 1st 8-bytes is a pointer to a function
        data = br.read64()
        if bv.get_function_at(data) is None:
            return None
        # 2. read two 4-byte integers and ensure  first < second
        first = br.read32()
        second = br.read32()
        if not first < second:
            return None
        # 3. read 4-byte maxsize field is > 0
        maxsize = br.read32()
        if not maxsize > 0:
            return None
        # 4. read 4-byte padding and then read 8-byte reserved and ensure == 0
        padding = br.read32()
        if not padding == 0:
            log_info("padding is not 0")
        reserved = br.read64()
        if not reserved == 0:
            return None
        return MIGSubsystem(addr, first, second-first)


class MigCreator(object):
    """
    Creates unique Mig subsystem structures based
    on the MIG subsystem ID and number of handlers found.
    """

    def __init__(self, bv: BinaryView):
        self._bv = bv

    def create(self, migs: List[int]):
        """
        Create Mig Subsytem structures at the addresses
        found in `migs`.
        """
        pass


def find_mig_handlers(bv: BinaryView):
    mf = MigFinder(bv)
    mc = MigCreator(bv)
    migs = mf.find()
    if len(migs) == 0:
        return
    mc.create(migs)


def is_mig_valid(bv: BinaryView):
    if "mac" not in bv.platform.name:
        return False
    if bv.get_symbols_by_name("_NDR_record") is None:
        return False


PluginCommand.register(
    "MigFinder",
    "Find MIG IPC Server Handlers",
    find_mig_handlers,
    is_valid=is_mig_valid,
)
