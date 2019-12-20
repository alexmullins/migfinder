from typing import List, Optional
from binaryninja import BinaryView, PluginCommand


class MigFinder(object):
    """
    Searches a programs DATA and CONST sections looking
    for possible Mig Subsytem handler's using data heuristics
    to find them.
    """

    def __init__(self, bv: BinaryView):
        self._bv = bv

    def find() -> Optional[List[int]]:
        """
        Find all of the possible MIG Handlers in the programs
        DATA and CONST sections.
        Returns a list of address where each Mig Subsystem starts
        or None if none are found.
        """
        pass


class MigCreator(object):
    """
    Creates unique Mig subsystem structures based
    on the MIG ID and number of handlers found.
    """

    def __init__(self, bv: BinaryView):
        self._bv = bv

    def create(migs: List[int]):
        """
        Create Mig Subsytem structures at the addresses
        found in `migs`.
        """
        pass


def find_mig_handlers(bv: BinaryView):
    mf = MigFinder(bv)
    mc = MigCreator(bv)

    migs = mf.find()
    if migs is None:
        return

    mc.create(migs)


def is_mig_valid(bv: BinaryView):
    if "mac" not in bv.platform:
        return False
    if bv.get_symbols_by_name("_NDR_record") is None:
        return False


PluginCommand.register(
    "MigFinder",
    "Find MIG IPC Server Handlers",
    find_mig_handlers,
    is_valid=is_mig_valid,
)
