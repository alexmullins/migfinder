from collections import namedtuple
from typing import List

from binaryninja import (BinaryReader, BinaryView, PluginCommand, Section,
                         Type, log_info)


class MIGSubsystem:
    def __init__(self, addr, subsystem, num_entries):
        self.addr = addr
        self.subsystem = subsystem
        self.num_entries = num_entries

    def __repr__(self):
        return "MIGSubsytem(addr=%s, subsystem=%d, num_entries=%d)" % (
            hex(self.addr),
            self.subsystem,
            self.num_entries,
        )


class MigFinder:
    """
    Searches a programs DATA and CONST sections looking
    for possible Mig Subsytem handler's using data heuristics
    to find them.
    """

    def __init__(self, bv: BinaryView):
        self._bv = bv
        self._br = BinaryReader(bv)

    def __repr__(self):
        return

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
        return MIGSubsystem(addr, first, second - first)


class MigCreator:
    """
    Creates unique Mig subsystem structures based
    on the MIG subsystem ID and number of handlers found.
    """

    def __init__(self, bv: BinaryView):
        self._bv = bv

    def create(self, migs: List[MIGSubsystem]):
        """
        Create Mig Subsytem structures at the addresses
        found in `migs`, rename server functions, stub functions
        and handler functions.
        """
        pass


def find_mig_subsystems(bv: BinaryView):
    mf = MigFinder(bv)
    migs = mf.find()
    if len(migs) == 0:
        return

    mc = MigCreator(bv)
    mc.create(migs)


def is_mig_valid(bv: BinaryView):
    if bv.platform is None or "mac" not in bv.platform.name or bv.get_symbols_by_name("_NDR_record") is None:
        return False
    else:
        return True


def create_mig_subsystem_type(subsystem: int, num_handlers: int) -> Type:
    pass


PluginCommand.register(
    "MigFinder",
    "Find MIG IPC Server Subsystems",
    find_mig_subsystems,
    is_valid=is_mig_valid,
)
